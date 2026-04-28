// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "net/net.h"
#include "net/netbase.h"
#include "net/seeds.h"
#include "chain/chainstate.h"
#include "consensus/params.h"
#include "hash/keccak.h"
#include "util/random.h"
#include "util/time.h"

#include "uv.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <set>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include "logging.h"

namespace flow {

// ===========================================================================
// Seed nodes
// ===========================================================================

const std::vector<std::pair<std::string, uint16_t>> NetManager::SEED_NODES = {
    {"seed.flowcoin.org", consensus::MAINNET_PORT},
};

// ===========================================================================
// Write request context (attached to uv_write_t for cleanup)
// ===========================================================================

struct WriteContext {
    uv_write_t req;
    uv_buf_t buf;
    uint8_t* data;

    WriteContext(const uint8_t* src, size_t len) {
        data = new uint8_t[len];
        std::memcpy(data, src, len);
        buf = uv_buf_init(reinterpret_cast<char*>(data), static_cast<unsigned int>(len));
        req.data = this;
    }

    ~WriteContext() {
        delete[] data;
    }
};

// ===========================================================================
// Connect request context
// ===========================================================================

struct ConnectContext {
    uv_connect_t req;
    NetManager* netman;
    CNetAddr addr;
    uv_tcp_t* tcp_handle;
};

// ===========================================================================
// Construction / destruction
// ===========================================================================

NetManager::NetManager(ChainState& chain, uint16_t port, uint32_t magic)
    : chain_(chain)
    , port_(port)
    , magic_(magic)
    , local_nonce_(GetRandUint64())
    , handler_(chain, *this)
{
}

NetManager::~NetManager() {
    stop();
}

// ===========================================================================
// Start / stop / run
// ===========================================================================

bool NetManager::start() {
    if (running_.load()) return false;

    loop_ = uv_loop_new();
    if (!loop_) {
        LogError("net", "failed to create event loop");
        return false;
    }

    // Store NetManager pointer in loop data so callbacks can find us
    loop_->data = this;

    // Create and initialize the TCP server handle
    server_ = new uv_tcp_t;
    uv_tcp_init(loop_, server_);
    server_->data = this;

    // Bind to all interfaces — try dual-stack (IPv6+IPv4) first, fallback to IPv4
    int r;
    struct sockaddr_in6 bind_addr6;
    uv_ip6_addr("::", port_, &bind_addr6);
    r = uv_tcp_bind(server_, reinterpret_cast<const struct sockaddr*>(&bind_addr6), 0);
    if (r >= 0) {
        LogInfo("net", "Bound to [::]:%u", port_);
    } else {
        // IPv6 not available — fallback to IPv4 only
        LogInfo("net", "IPv6 bind failed (%s), falling back to IPv4", uv_strerror(r));
        uv_close(reinterpret_cast<uv_handle_t*>(server_), on_close);
        uv_run(loop_, UV_RUN_NOWAIT);

        server_ = new uv_tcp_t;
        uv_tcp_init(loop_, server_);
        server_->data = this;

        struct sockaddr_in bind_addr4;
        uv_ip4_addr("0.0.0.0", port_, &bind_addr4);
        r = uv_tcp_bind(server_, reinterpret_cast<const struct sockaddr*>(&bind_addr4), 0);
        if (r < 0) {
            LogError("net", "bind failed on port %u: %s", port_, uv_strerror(r));
            uv_close(reinterpret_cast<uv_handle_t*>(server_), on_close);
            server_ = nullptr;
            uv_run(loop_, UV_RUN_DEFAULT);
            uv_loop_close(loop_);
            uv_loop_delete(loop_);
            loop_ = nullptr;
            return false;
        }
        LogInfo("net", "Bound to 0.0.0.0:%u", port_);
    }

    // Start listening
    r = uv_listen(reinterpret_cast<uv_stream_t*>(server_), 128, on_new_connection);
    if (r < 0) {
        LogError("net", "listen failed on port %u: %s", port_, uv_strerror(r));
        // Close the handle properly before deleting the loop: schedule close,
        // run the loop to let the callback fire, then delete.
        uv_close(reinterpret_cast<uv_handle_t*>(server_), on_close);
        server_ = nullptr;
        uv_run(loop_, UV_RUN_DEFAULT);
        uv_loop_close(loop_);
        uv_loop_delete(loop_);
        loop_ = nullptr;
        return false;
    }

    // (Bound-to lines already emitted above.)

    // Create periodic timer (fires every 30 seconds)
    timer_ = new uv_timer_t;
    uv_timer_init(loop_, timer_);
    timer_->data = this;
    uv_timer_start(timer_, on_timer, 1000, 30000);  // first tick after 1s, then every 30s

    // Create async handle for stopping the loop from another thread
    stop_async_ = new uv_async_t;
    uv_async_init(loop_, stop_async_, on_stop_async);
    stop_async_->data = this;

    running_.store(true);

    // Load previously known peers from peers.dat
    load_peers();

    // Seeds are no longer injected into addrman at startup — that caused
    // duplicate connections when the hardcoded IP and the DNS-resolved IP
    // were the same host. DNS seeding runs first on the next tick, and
    // hardcoded IPs are only added if DNS returns nothing.
    int64_t now = GetTime();

    // Initialize timing
    last_feeler_time_ = now;
    last_peers_save_time_ = now;
    last_cleanup_time_ = now;
    last_dns_seed_time_ = 0;  // Will trigger DNS resolution on first tick

    return true;
}

void NetManager::stop() {
    if (!running_.load()) return;
    running_.store(false);

    // Save peers.dat before shutting down
    save_peers();

    if (stop_async_) {
        uv_async_send(stop_async_);
    }
}

void NetManager::on_stop_async(uv_async_t* handle) {
    NetManager* self = static_cast<NetManager*>(handle->data);

    // Close timer
    if (self->timer_) {
        uv_timer_stop(self->timer_);
        uv_close(reinterpret_cast<uv_handle_t*>(self->timer_), on_close);
        self->timer_ = nullptr;
    }

    // Disconnect all peers
    {
        std::lock_guard<std::mutex> lock(self->peers_mutex_);
        for (auto& [id, peer] : self->peers_) {
            if (peer->tcp_handle()) {
                auto* tcp = static_cast<uv_tcp_t*>(peer->tcp_handle());
                if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(tcp))) {
                    uv_close(reinterpret_cast<uv_handle_t*>(tcp), on_close);
                }
                peer->set_tcp_handle(nullptr);
            }
            peer->set_state(PeerState::DISCONNECTED);
        }
    }

    // Close server
    if (self->server_) {
        uv_close(reinterpret_cast<uv_handle_t*>(self->server_), on_close);
        self->server_ = nullptr;
    }

    // Close the async handle itself
    uv_close(reinterpret_cast<uv_handle_t*>(handle), on_close);
    self->stop_async_ = nullptr;

    // Stop the event loop
    uv_stop(self->loop_);
}

void NetManager::run() {
    if (!loop_) return;

    uv_run(loop_, UV_RUN_DEFAULT);

    // Drain remaining close callbacks
    uv_run(loop_, UV_RUN_DEFAULT);

    // Force-close any remaining handles
    uv_walk(loop_, [](uv_handle_t* handle, void*) {
        if (!uv_is_closing(handle)) {
            uv_close(handle, nullptr);
        }
    }, nullptr);
    uv_run(loop_, UV_RUN_DEFAULT);

    // Cleanup after loop exits
    uv_loop_close(loop_);
    uv_loop_delete(loop_);
    loop_ = nullptr;

    // Clear all peers
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peers_.clear();
}

// ===========================================================================
// Connection management
// ===========================================================================

void NetManager::connect_to(const CNetAddr& addr) {
    if (!loop_ || !running_.load()) return;

    // Skip null/unroutable addresses (::, 0.0.0.0, etc.)
    bool all_zero = true;
    for (int i = 0; i < 16; i++) {
        if (addr.ip[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) return;  // skip :: and 0.0.0.0

    // Don't connect to our own address
    if (is_self_address(addr)) {
        LogInfo("net", "skipping self-address %s", addr.to_string().c_str());
        return;
    }

    // Don't connect if we already have too many outbound peers
    if (outbound_count() >= static_cast<size_t>(consensus::MAX_OUTBOUND_PEERS)) {
        return;
    }

    // Don't connect to peers we're already connected to (check by IP, not port,
    // because inbound peers have ephemeral ports)
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& [id, peer] : peers_) {
            if (peer->state() == PeerState::DISCONNECTED) continue;
            if (!peer->is_inbound() && std::memcmp(peer->addr().ip, addr.ip, 16) == 0) {
                return;  // already have outbound connection to this IP
            }
        }
    }

    // Create a new TCP handle for the outbound connection
    auto* tcp = new uv_tcp_t;
    uv_tcp_init(loop_, tcp);

    // Create connection context
    auto* ctx = new ConnectContext;
    ctx->netman = this;
    ctx->addr = addr;
    ctx->tcp_handle = tcp;
    ctx->req.data = ctx;

    // Resolve the address
    struct sockaddr_in dest;
    if (addr.is_ipv4()) {
        char ip_str[16];
        std::snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                      addr.ip[12], addr.ip[13], addr.ip[14], addr.ip[15]);
        uv_ip4_addr(ip_str, addr.port, &dest);
    } else {
        // IPv6 connection support
        struct sockaddr_in6 dest6;
        char ip6_str[INET6_ADDRSTRLEN];
        struct in6_addr addr6_raw;
        std::memcpy(&addr6_raw, addr.ip, 16);
        inet_ntop(AF_INET6, &addr6_raw, ip6_str, sizeof(ip6_str));
        uv_ip6_addr(ip6_str, addr.port, &dest6);

        addrman_.mark_failed(addr);

        int r6 = uv_tcp_connect(&ctx->req, tcp,
                                reinterpret_cast<const struct sockaddr*>(&dest6),
                                on_connect);
        if (r6 < 0) {
            LogError("net", "connect to %s failed: %s",
                    addr.to_string().c_str(), uv_strerror(r6));
            delete ctx;
            uv_close(reinterpret_cast<uv_handle_t*>(tcp), on_close);
        }
        return;
    }

    addrman_.mark_failed(addr);  // pre-mark as tried; mark_good on success

    int r = uv_tcp_connect(&ctx->req, tcp,
                           reinterpret_cast<const struct sockaddr*>(&dest),
                           on_connect);
    if (r < 0) {
        LogError("net", "connect to %s failed: %s",
                addr.to_string().c_str(), uv_strerror(r));
        delete ctx;
        uv_close(reinterpret_cast<uv_handle_t*>(tcp), on_close);
    }
}

void NetManager::send_to(Peer& peer, const std::vector<uint8_t>& data) {
    if (peer.state() == PeerState::DISCONNECTED) return;
    if (!peer.tcp_handle()) return;

    auto* ctx = new WriteContext(data.data(), data.size());
    auto* tcp = static_cast<uv_tcp_t*>(peer.tcp_handle());

    int r = uv_write(&ctx->req, reinterpret_cast<uv_stream_t*>(tcp),
                     &ctx->buf, 1, on_write);
    if (r < 0) {
        LogError("net", "write to peer %lu failed: %s",
                (unsigned long)peer.id(), uv_strerror(r));
        delete ctx;
        return;
    }

    peer.add_bytes_sent(data.size());
}

void NetManager::disconnect(Peer& peer, const std::string& reason) {
    if (peer.state() == PeerState::DISCONNECTED) return;

    LogInfo("net", "disconnecting peer %lu (%s): %s",
            (unsigned long)peer.id(), peer.addr().to_string().c_str(),
            reason.c_str());

    peer.set_state(PeerState::DISCONNECTED);

    if (peer.tcp_handle()) {
        auto* tcp = static_cast<uv_tcp_t*>(peer.tcp_handle());
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(tcp))) {
            uv_close(reinterpret_cast<uv_handle_t*>(tcp), on_close);
        }
        peer.set_tcp_handle(nullptr);
    }
}

std::vector<Peer*> NetManager::get_peers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::vector<Peer*> result;
    result.reserve(peers_.size());
    for (const auto& [id, peer] : peers_) {
        if (peer->state() != PeerState::DISCONNECTED) {
            result.push_back(peer.get());
        }
    }
    return result;
}

std::vector<Peer*> NetManager::connected_peers() const {
    return get_peers();
}

size_t NetManager::peer_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    size_t count = 0;
    for (const auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::DISCONNECTED) continue;
        ++count;
    }
    return count;
}

size_t NetManager::outbound_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    size_t count = 0;
    for (const auto& [id, peer] : peers_) {
        if (peer->is_inbound() || peer->state() == PeerState::DISCONNECTED) continue;
        ++count;
    }
    return count;
}

size_t NetManager::inbound_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    size_t count = 0;
    for (const auto& [id, peer] : peers_) {
        if (!peer->is_inbound() || peer->state() == PeerState::DISCONNECTED) continue;
        ++count;
    }
    return count;
}

void NetManager::broadcast(const std::string& command, const std::vector<uint8_t>& payload) {
    auto msg = build_message(magic_, command, payload);
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::HANDSHAKE_DONE) {
            send_to(*peer, msg);
        }
    }
}

void NetManager::broadcast_except(const std::string& command, const std::vector<uint8_t>& payload,
                                   const Peer* exclude) {
    auto msg = build_message(magic_, command, payload);
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::HANDSHAKE_DONE) {
            if (exclude && peer->id() == exclude->id()) continue;
            send_to(*peer, msg);
        }
    }
}

// ===========================================================================
// Peer creation / removal
// ===========================================================================

Peer& NetManager::create_peer(const CNetAddr& addr, bool inbound, uv_tcp_t* handle) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    uint64_t id = next_peer_id_++;
    auto peer = std::make_unique<Peer>(id, addr, inbound);
    peer->set_tcp_handle(handle);
    peer->set_connect_time(GetTime());

    // Store the peer id in the tcp handle's data field for callback lookup
    handle->data = reinterpret_cast<void*>(static_cast<uintptr_t>(id));

    Peer& ref = *peer;
    peers_[id] = std::move(peer);
    return ref;
}

void NetManager::remove_peer(uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peers_.erase(peer_id);
}

// ===========================================================================
// libuv callbacks
// ===========================================================================

void NetManager::on_new_connection(uv_stream_t* server, int status) {
    NetManager* self = static_cast<NetManager*>(server->data);

    if (status < 0) {
        LogError("net", "new connection error: %s", uv_strerror(status));
        return;
    }

    // Check if we have room for inbound peers; try eviction first
    if (self->inbound_count() >= static_cast<size_t>(consensus::MAX_INBOUND_PEERS)) {
        self->evict_inbound_if_needed();

        // Check again after eviction attempt
        if (self->inbound_count() >= static_cast<size_t>(consensus::MAX_INBOUND_PEERS)) {
            auto* client = new uv_tcp_t;
            uv_tcp_init(self->loop_, client);
            if (uv_accept(server, reinterpret_cast<uv_stream_t*>(client)) == 0) {
                uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
            } else {
                delete client;
            }
            return;
        }
    }

    auto* client = new uv_tcp_t;
    uv_tcp_init(self->loop_, client);

    if (uv_accept(server, reinterpret_cast<uv_stream_t*>(client)) != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
        return;
    }

    // Get the remote address
    struct sockaddr_storage addr_storage;
    int namelen = sizeof(addr_storage);
    uv_tcp_getpeername(client, reinterpret_cast<struct sockaddr*>(&addr_storage), &namelen);

    CNetAddr remote_addr;
    if (addr_storage.ss_family == AF_INET) {
        auto* addr4 = reinterpret_cast<struct sockaddr_in*>(&addr_storage);
        // Store as IPv4-mapped
        std::memset(remote_addr.ip, 0, 10);
        remote_addr.ip[10] = 0xff;
        remote_addr.ip[11] = 0xff;
        std::memcpy(&remote_addr.ip[12], &addr4->sin_addr.s_addr, 4);
        remote_addr.port = ntohs(addr4->sin_port);
    } else if (addr_storage.ss_family == AF_INET6) {
        auto* addr6 = reinterpret_cast<struct sockaddr_in6*>(&addr_storage);
        std::memcpy(remote_addr.ip, &addr6->sin6_addr, 16);
        remote_addr.port = ntohs(addr6->sin6_port);
    }

    // Check if this address is banned
    if (self->banman_.is_banned(remote_addr)) {
        LogError("net", "rejected banned inbound connection from %s",
                remote_addr.to_string().c_str());
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
        return;
    }

    LogInfo("net", "inbound connection from %s",
            remote_addr.to_string().c_str());

    // Create peer entry
    Peer& peer = self->create_peer(remote_addr, true, client);

    // Start reading from this connection
    uv_read_start(reinterpret_cast<uv_stream_t*>(client), on_alloc, on_read);

    // Inbound peers: we wait for their version message before sending ours
    (void)peer;
}

void NetManager::on_connect(uv_connect_t* req, int status) {
    auto* ctx = static_cast<ConnectContext*>(req->data);
    NetManager* self = ctx->netman;

    if (status < 0) {
        LogDebug("net", "outbound connect to %s failed: %s",
                ctx->addr.to_string().c_str(), uv_strerror(status));
        self->addrman_.mark_failed(ctx->addr);
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->tcp_handle), on_close);
        delete ctx;
        return;
    }

    LogInfo("net", "connected to %s", ctx->addr.to_string().c_str());

    // Create peer entry
    Peer& peer = self->create_peer(ctx->addr, false, ctx->tcp_handle);

    // Start reading
    uv_read_start(reinterpret_cast<uv_stream_t*>(ctx->tcp_handle), on_alloc, on_read);

    // Send our version message (outbound initiates)
    self->handler_.send_version(peer);

    delete ctx;
}

void NetManager::on_alloc(uv_handle_t* /*handle*/, size_t suggested_size, uv_buf_t* buf) {
    // Allocate a read buffer (capped to avoid excessive allocation)
    size_t alloc_size = std::min(suggested_size, static_cast<size_t>(65536));
    buf->base = new char[alloc_size];
    buf->len = static_cast<decltype(buf->len)>(alloc_size);
}

void NetManager::on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    auto* tcp = reinterpret_cast<uv_tcp_t*>(stream);
    uint64_t peer_id = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(tcp->data));

    // Find the NetManager from the loop data
    // We get it from the server handle's loop
    uv_loop_t* loop = tcp->loop;
    // Walk all handles to find the server... actually, we store NetManager* differently.
    // The server handle has NetManager* in its data field.
    // For peer handles, data is the peer_id. We need NetManager* from somewhere.
    // Solution: store NetManager* in the loop's data field.
    NetManager* self = static_cast<NetManager*>(loop->data);

    if (nread < 0) {
        // Connection closed or error
        if (nread != UV_EOF) {
            LogError("net", "read error on peer %lu: %s",
                    (unsigned long)peer_id, uv_strerror(static_cast<int>(nread)));
        }

        // Find and disconnect the peer
        {
            std::lock_guard<std::mutex> lock(self->peers_mutex_);
            auto it = self->peers_.find(peer_id);
            if (it != self->peers_.end()) {
                it->second->set_state(PeerState::DISCONNECTED);
                it->second->set_tcp_handle(nullptr);
            }
        }

        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(tcp))) {
            uv_close(reinterpret_cast<uv_handle_t*>(tcp), on_close);
        }

        delete[] buf->base;
        return;
    }

    if (nread == 0) {
        delete[] buf->base;
        return;
    }

    // Append received data to the peer's buffer, then process messages
    // outside the peers_mutex_ lock.  process_recv dispatches to message
    // handlers that may call broadcast() or relay_block(), which also
    // acquire peers_mutex_.  Holding the lock here would deadlock.
    Peer* peer_ptr = nullptr;
    {
        std::lock_guard<std::mutex> lock(self->peers_mutex_);
        auto it = self->peers_.find(peer_id);
        if (it != self->peers_.end()) {
            Peer& peer = *it->second;
            peer.recv_buffer().insert(peer.recv_buffer().end(),
                                      buf->base, buf->base + nread);
            peer.add_bytes_recv(static_cast<uint64_t>(nread));
            peer_ptr = &peer;
        }
    }

    // Process messages without holding peers_mutex_.  This is safe
    // because libuv callbacks run on a single thread, so no other
    // callback can remove the peer while we are executing here.
    if (peer_ptr) {
        self->process_recv(*peer_ptr);

        // Check if peer should be banned (no lock needed — single thread)
        if (peer_ptr->should_ban()) {
            self->disconnect(*peer_ptr, "misbehavior ban");
        }
    }

    delete[] buf->base;
}

void NetManager::on_write(uv_write_t* req, int status) {
    auto* ctx = static_cast<WriteContext*>(req->data);
    if (status < 0) {
        LogError("net", "write error: %s", uv_strerror(status));
    }
    delete ctx;
}

void NetManager::on_timer(uv_timer_t* timer) {
    NetManager* self = static_cast<NetManager*>(timer->data);
    self->on_tick();
}

void NetManager::on_close(uv_handle_t* handle) {
    // The handle memory was allocated with new; free it.
    // But we need to be careful: server_, timer_, and stop_async_ are
    // also closed through this callback. We use the type to distinguish.
    // Actually, all dynamic uv handles were allocated with new, so we
    // always delete them here.

    // Note: server_, timer_, stop_async_ pointers are set to nullptr
    // before closing, and on_close frees the memory.
    // For peer tcp handles, they are also allocated with new.
    switch (handle->type) {
        case UV_TCP:
            delete reinterpret_cast<uv_tcp_t*>(handle);
            break;
        case UV_TIMER:
            delete reinterpret_cast<uv_timer_t*>(handle);
            break;
        case UV_ASYNC:
            delete reinterpret_cast<uv_async_t*>(handle);
            break;
        default:
            // Should not happen, but clean up anyway
            std::free(handle);
            break;
    }
}

// ===========================================================================
// Message processing
// ===========================================================================

void NetManager::process_recv(Peer& peer) {
    auto& buf = peer.recv_buffer();
    size_t messages_processed = 0;

    while (buf.size() >= MessageHeader::SIZE) {
        // Try to parse a header from the buffer
        DataReader r(buf.data(), buf.size());
        MessageHeader hdr;
        if (!MessageHeader::deserialize(r, hdr)) {
            // Not enough data or parse error
            break;
        }

        // Validate magic bytes
        if (hdr.magic != magic_) {
            LogError("net", "bad magic from peer %lu (got 0x%08x, expected 0x%08x)",
                    (unsigned long)peer.id(), hdr.magic, magic_);
            peer.add_misbehavior(50);
            buf.clear();
            return;
        }

        // Validate payload size
        if (hdr.payload_size > MessageHeader::MAX_PAYLOAD_SIZE) {
            LogError("net", "oversized payload from peer %lu: %u bytes",
                    (unsigned long)peer.id(), hdr.payload_size);
            peer.add_misbehavior(50);
            buf.clear();
            return;
        }

        // Check if we have the complete message (header + payload)
        size_t total_size = MessageHeader::SIZE + hdr.payload_size;
        if (buf.size() < total_size) {
            LogDebug("net", "partial message '%s' from peer %lu: have %zu of %zu bytes",
                    hdr.command_string().c_str(), (unsigned long)peer.id(),
                    buf.size(), total_size);
            break;  // wait for more data
        }

        // Verify checksum
        const uint8_t* payload_ptr = buf.data() + MessageHeader::SIZE;
        uint32_t expected_checksum = compute_checksum(payload_ptr, hdr.payload_size);
        if (hdr.checksum != expected_checksum) {
            LogError("net", "bad checksum from peer %lu on '%s'",
                    (unsigned long)peer.id(), hdr.command_string().c_str());
            peer.add_misbehavior(10);
            // Skip this message
            buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(total_size));
            continue;
        }

        // Extract command string
        std::string command = hdr.command_string();

        LogDebug("net", "recv msg '%s' (%u bytes payload) from peer %lu [msg #%lu in batch]",
                command.c_str(), hdr.payload_size,
                (unsigned long)peer.id(),
                (unsigned long)(messages_processed + 1));

        // Dispatch to message handler
        handler_.process_message(peer, command, payload_ptr, hdr.payload_size);

        // Remove the processed message from the buffer
        buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(total_size));
        messages_processed++;
    }

    if (messages_processed > 1) {
        LogInfo("net", "processed %zu messages in batch from peer %lu",
                messages_processed, (unsigned long)peer.id());
    }

    // Safety: if the buffer is growing too large without producing valid messages,
    // disconnect the peer to prevent memory exhaustion
    if (buf.size() > 4 * 1024 * 1024) {
        LogError("net", "recv buffer overflow for peer %lu (%zu bytes)",
                (unsigned long)peer.id(), buf.size());
        disconnect(peer, "recv buffer overflow");
    }
}

// ===========================================================================
// Periodic maintenance
// ===========================================================================

void NetManager::on_tick() {
    if (!running_.load()) return;

    int64_t now = GetTime();

    // Ping all handshaked peers that haven't been pinged recently
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto& [id, peer] : peers_) {
            if (peer->state() != PeerState::HANDSHAKE_DONE) continue;

            // Ping every 2 minutes
            if (now - peer->last_ping_time() / 1000000 >= 120) {
                uint64_t nonce = GetRandUint64();
                peer->set_ping_nonce(nonce);
                peer->set_last_ping_time(GetTimeMicros());

                DataWriter w;
                w.write_u64_le(nonce);
                auto msg = build_message(magic_, NetCmd::PING, w.release());
                send_to(*peer, msg);
            }

            // Disconnect peers stuck in handshake for over 60 seconds
            if (peer->state() != PeerState::HANDSHAKE_DONE &&
                peer->state() != PeerState::DISCONNECTED &&
                now - peer->connect_time() > 60) {
                disconnect(*peer, "handshake timeout");
            }

            // Ban check: if misbehavior threshold reached, ban and disconnect
            if (peer->should_ban() && peer->state() != PeerState::DISCONNECTED) {
                banman_.ban(peer->addr());
                disconnect(*peer, "misbehavior ban");
            }
        }

        // Clean up disconnected peers (remove entries older than 60 seconds)
        std::vector<uint64_t> to_remove;
        for (auto& [id, peer] : peers_) {
            if (peer->state() == PeerState::DISCONNECTED &&
                now - peer->connect_time() > 60) {
                to_remove.push_back(id);
            }
        }
        for (uint64_t id : to_remove) {
            peers_.erase(id);
        }
    }

    // Rotate idle peers (20-minute no-message timeout)
    rotate_idle_peers(now);

    // Update bandwidth tracking for all peers
    update_peer_bandwidth(now);

    // Try to maintain outbound connections
    maintain_connections();

    // Feeler connections: every 2 minutes, try a random New table address
    if (now - last_feeler_time_ >= 120) {
        last_feeler_time_ = now;
        start_feeler();
    }

    // DNS seed resolution: on first tick and then every 11 minutes if we have few peers
    if (last_dns_seed_time_ == 0 ||
        (now - last_dns_seed_time_ >= 660 && addrman_.size() < 100)) {
        last_dns_seed_time_ = now;
        resolve_dns_seeds();
    }

    // Sweep expired bans periodically (every 5 minutes)
    if (now - last_cleanup_time_ >= 300) {
        last_cleanup_time_ = now;
        banman_.sweep();
        addrman_.cleanup();
    }

    // Save peers.dat every 15 minutes.
    if (now - last_peers_save_time_ >= 900) {
        last_peers_save_time_ = now;
        addrman_.cleanup();
        save_peers();
    }
}

void NetManager::connect_seeds() {
    for (const auto& [ip, p] : SEED_NODES) {
        CNetAddr addr(ip, p);
        connect_to(addr);
    }
}

void NetManager::maintain_connections() {
    size_t current_outbound = outbound_count();
    size_t target = static_cast<size_t>(consensus::MAX_OUTBOUND_PEERS);

    if (current_outbound >= target) return;

    size_t needed = target - current_outbound;
    size_t attempts = 0;
    static constexpr size_t MAX_CONNECT_ATTEMPTS = 30;

    LogDebug("net", "maintain_connections: outbound=%zu target=%zu needed=%zu addrman_size=%zu (new=%zu tried=%zu)",
            current_outbound, target, needed,
            addrman_.size(), addrman_.new_size(), addrman_.tried_size());

    // Try to connect to addresses from the address manager
    for (size_t i = 0; i < needed && attempts < MAX_CONNECT_ATTEMPTS; ++attempts) {
        CNetAddr addr = addrman_.select();
        if (addr.port == 0) {
            LogDebug("net", "maintain_connections: addrman.select() returned no candidate (attempt %zu)", attempts);
            // No candidates available; try seeds if we have no connections at all
            if (current_outbound == 0 && i == 0) {
                connect_seeds();
            }
            break;
        }

        LogDebug("net", "maintain_connections: selected %s from addrman", addr.to_string().c_str());

        // Check ban status before attempting connection
        if (banman_.is_banned(addr)) {
            continue;
        }

        // Check subnet diversity: prefer connecting to different /16 subnets
        if (!has_subnet_diversity(addr)) {
            continue;
        }

        connect_to(addr);
        i++;
    }
}

// ===========================================================================
// High-level broadcast helpers (called by RPC / mining)
// ===========================================================================

void NetManager::broadcast_transaction(const CTransaction& tx) {
    uint256 txid = tx.get_txid();

    DataWriter w;
    w.write_compact_size(1);
    w.write_u32_le(static_cast<uint32_t>(INV_TX));
    w.write_bytes(txid.data(), 32);

    broadcast(NetCmd::INV, w.release());
}

void NetManager::broadcast_block(const uint256& block_hash) {
    DataWriter w;
    w.write_compact_size(1);
    w.write_u32_le(static_cast<uint32_t>(INV_BLOCK));
    w.write_bytes(block_hash.data(), 32);

    broadcast(NetCmd::INV, w.release());
}

bool NetManager::add_node(const std::string& ip, uint16_t port) {
    CNetAddr addr(ip, port);
    if (addr.port == 0) return false;

    addrman_.add(addr, GetTime());
    connect_to(addr);
    return true;
}

// ===========================================================================
// Feeler connections
// ===========================================================================

void NetManager::start_feeler() {
    // Feeler connections test reachability of addresses in addrman.New
    // without maintaining a persistent connection. After the handshake
    // completes, the feeler is immediately disconnected.
    CNetAddr addr = addrman_.select_from_new();
    if (addr.port == 0) return;

    // Skip null/unroutable addresses
    bool all_zero = true;
    for (int i = 0; i < 16; i++) {
        if (addr.ip[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) return;

    // Don't feeler to addresses we're already connected to
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& [id, peer] : peers_) {
            if (peer->addr() == addr && peer->state() != PeerState::DISCONNECTED) {
                return;
            }
        }
    }

    // Check ban status
    if (banman_.is_banned(addr)) return;

    // Don't feeler if we already have too many outbound
    if (outbound_count() >= static_cast<size_t>(consensus::MAX_OUTBOUND_PEERS)) return;

    LogDebug("net", "starting feeler connection to %s",
            addr.to_string().c_str());

    connect_to(addr);

    // Mark the peer as a feeler (we'll set the flag after creation)
    // The on_connect callback will handle this via addr matching
}

// ===========================================================================
// Eviction logic
// ===========================================================================

Peer* NetManager::select_eviction_candidate() {
    // When we're at MAX_INBOUND, we need to select a peer to evict.
    // Protection strategy (Bitcoin Core style):
    //   1. Protect the 4 peers with lowest latency
    //   2. Protect the 4 peers with longest connection time
    //   3. Protect the 8 peers with best services
    //   4. Protect peers from unique /16 subnets
    //   5. Evict the peer with highest latency from the unprotected set

    std::vector<Peer*> candidates;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto& [id, peer] : peers_) {
            if (peer->is_inbound() &&
                peer->state() == PeerState::HANDSHAKE_DONE) {
                candidates.push_back(peer.get());
            }
        }
    }

    if (candidates.size() <= 8) return nullptr;  // Not enough to evict

    // Sort by eviction score (lowest score = best candidate for eviction)
    std::sort(candidates.begin(), candidates.end(),
              [](const Peer* a, const Peer* b) {
                  return a->eviction_score() < b->eviction_score();
              });

    // Protect top half by eviction score
    size_t protect_count = candidates.size() / 2;
    protect_count = std::min(protect_count, static_cast<size_t>(16));

    // The eviction candidate is the one with the lowest score
    // (at the front after sorting)
    if (!candidates.empty()) {
        return candidates.front();
    }

    return nullptr;
}

void NetManager::evict_inbound_if_needed() {
    if (inbound_count() < static_cast<size_t>(consensus::MAX_INBOUND_PEERS)) return;

    Peer* victim = select_eviction_candidate();
    if (victim) {
        disconnect(*victim, "evicted for new inbound");
    }
}

// ===========================================================================
// Peer rotation: disconnect idle peers
// ===========================================================================

void NetManager::rotate_idle_peers(int64_t now) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    for (auto& [id, peer] : peers_) {
        if (peer->state() != PeerState::HANDSHAKE_DONE) continue;

        // Disconnect peers idle for > 20 minutes without any messages
        if (peer->last_recv_time() > 0 && now - peer->last_recv_time() > 1200) {
            disconnect(*peer, "idle timeout (20 min no messages)");
            continue;
        }

        // Disconnect feeler connections after successful handshake
        if (peer->is_feeler() && peer->state() == PeerState::HANDSHAKE_DONE) {
            addrman_.mark_good(peer->addr());
            disconnect(*peer, "feeler connection complete");
            continue;
        }
    }
}

// ===========================================================================
// Bandwidth tracking
// ===========================================================================

void NetManager::update_peer_bandwidth(int64_t now) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    for (auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::DISCONNECTED) continue;
        peer->update_bandwidth(now);
        peer->prune_inventory();
    }
}

// ===========================================================================
// Connection diversity
// ===========================================================================

bool NetManager::has_subnet_diversity(const CNetAddr& addr) const {
    // Check how many outbound peers we have from the same /16 subnet
    uint16_t target_subnet = 0;
    if (addr.is_ipv4()) {
        target_subnet = static_cast<uint16_t>((addr.ip[12] << 8) | addr.ip[13]);
    } else {
        target_subnet = static_cast<uint16_t>((addr.ip[0] << 8) | addr.ip[1]);
    }

    int same_subnet_count = 0;
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (const auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::DISCONNECTED) continue;
        if (!peer->is_inbound() && peer->get_subnet_id() == target_subnet) {
            same_subnet_count++;
        }
    }

    // Allow at most 2 outbound connections from the same subnet
    return same_subnet_count < 2;
}

// ===========================================================================
// DNS seed resolution
// ===========================================================================

void NetManager::resolve_dns_seeds() {
    static bool first_resolve = true;
    const auto& dns_seeds = GetDNSSeeds(magic_);

    int addrs_added = 0;

    for (const auto& seed_host : dns_seeds) {
        if (first_resolve)
            LogInfo("net", "resolving DNS seed %s", seed_host.c_str());

        auto addrs = LookupHost(seed_host, 256, true);
        if (addrs.empty()) {
            LogDebug("net", "DNS seed %s returned no results", seed_host.c_str());
            continue;
        }

        if (first_resolve)
            LogInfo("net", "DNS seed %s returned %zu addresses",
                    seed_host.c_str(), addrs.size());

        int64_t now = GetTime();
        for (const auto& net_addr : addrs) {
            // Convert CNetAddr2 to CNetAddr for compatibility
            CNetAddr addr;
            std::memcpy(addr.ip, net_addr.GetBytes(), 16);
            addr.port = consensus::MAINNET_PORT;

            addrman_.add(addr, now);
            ++addrs_added;
        }
    }

    // Fallback: only when DNS produced nothing AND addrman is effectively
    // empty do we fall back to the hardcoded IPs. This is the "DNS
    // censored / firewalled" case. Otherwise we stay on DNS results to
    // avoid the seed-IP appearing twice (once via DNS, once hardcoded).
    if (addrs_added == 0 && addrman_.size() == 0) {
        const auto& seeds = GetSeeds(magic_);
        int64_t now = GetTime();
        for (const auto& seed : seeds) {
            CNetAddr addr(seed.host, seed.port);
            // Skip entries that are themselves hostnames (DNS will handle them
            // when it comes back online); only add literal IPs.
            if (addr.ip[0] == 0 && addr.ip[1] == 0) continue;  // parse failed
            addrman_.add(addr, now);
            ++addrs_added;
        }
        if (addrs_added > 0) {
            LogInfo("net", "DNS seeding returned nothing — falling back to %d hardcoded IPs",
                    addrs_added);
        }
    }

    first_resolve = false;
}

// ===========================================================================
// get_peer_info — for RPC getpeerinfo
// ===========================================================================

std::vector<NetManager::PeerInfo> NetManager::get_peer_info() const {
    std::vector<PeerInfo> result;
    std::lock_guard<std::mutex> lock(peers_mutex_);

    for (const auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::DISCONNECTED) continue;

        PeerInfo info;
        info.id = peer->id();
        info.addr = peer->addr().to_string();
        info.services = peer->services();
        info.last_send = peer->last_send_time();
        info.last_recv = peer->last_recv_time();
        info.conntime = peer->connect_time();
        info.ping_time = peer->ping_latency_us();
        info.min_ping = peer->min_ping_us();
        info.version = peer->protocol_version();
        info.subver = peer->user_agent();
        info.inbound = peer->is_inbound();
        info.startingheight = peer->start_height();
        info.banscore = peer->misbehavior_score();
        info.synced_headers = peer->synced_headers();
        info.synced_blocks = peer->synced_blocks();
        info.bytes_sent = peer->bytes_sent();
        info.bytes_recv = peer->bytes_recv();
        info.send_bandwidth = peer->send_bandwidth();
        info.recv_bandwidth = peer->recv_bandwidth();
        info.prefers_headers = peer->prefers_headers();
        info.compact_blocks = peer->supports_compact_blocks();
        info.fee_filter = peer->fee_filter();

        result.push_back(info);
    }

    return result;
}

// ===========================================================================
// peers.dat persistence
// ===========================================================================

void NetManager::save_peers() {
    if (data_dir_.empty()) return;
    std::string path = data_dir_ + "/peers.dat";
    addrman_.save_to_file(path);
}

void NetManager::load_peers() {
    if (data_dir_.empty()) return;
    std::string path = data_dir_ + "/peers.dat";
    if (!addrman_.load_from_file(path)) {
        LogInfo("net", "no peers.dat found, starting fresh");
    }
}

// ===========================================================================
// Full connection lifecycle: connect_to with DNS resolution
// ===========================================================================

bool NetManager::connect_to_host(const std::string& addr_str) {
    if (!running_.load()) return false;

    // Parse host:port
    std::string host;
    uint16_t port = consensus::MAINNET_PORT;

    size_t colon = addr_str.rfind(':');
    if (colon != std::string::npos && colon > 0) {
        host = addr_str.substr(0, colon);
        int port_val = std::atoi(addr_str.substr(colon + 1).c_str());
        if (port_val > 0 && port_val <= 65535) {
            port = static_cast<uint16_t>(port_val);
        }
    } else {
        host = addr_str;
    }

    if (host.empty()) {
        LogInfo("net", "empty host in connect_to_host");
        return false;
    }

    // Strip brackets from IPv6 addresses [::1]
    if (host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }

    // Try direct IP parse first
    CNetAddr addr(host, port);
    if (addr.port > 0) {
        // Check if already connected
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (const auto& [id, peer] : peers_) {
                if (peer->addr() == addr && peer->state() != PeerState::DISCONNECTED) {
                    LogInfo("net", "already connected to %s", addr_str.c_str());
                    return false;
                }
            }
        }

        // Check if banned
        if (banman_.is_banned(addr)) {
            LogError("net", "cannot connect to banned address %s", addr_str.c_str());
            return false;
        }

        connect_to(addr);
        return true;
    }

    // DNS resolve if it's a hostname
    LogInfo("net", "resolving hostname %s", host.c_str());
    auto resolved = LookupHost(host, 1, false);
    if (resolved.empty()) {
        LogError("net", "failed to resolve %s", host.c_str());
        return false;
    }

    // Use the first resolved address
    CNetAddr resolved_addr;
    std::memcpy(resolved_addr.ip, resolved[0].GetBytes(), 16);
    resolved_addr.port = port;

    if (banman_.is_banned(resolved_addr)) {
        LogInfo("net", "resolved address %s is banned",
                resolved_addr.to_string().c_str());
        return false;
    }

    connect_to(resolved_addr);
    return true;
}

// ===========================================================================
// Outbound connection management with subnet diversity
// ===========================================================================

void NetManager::maintain_outbound_connections() {
    size_t current_outbound = outbound_count();
    size_t target = static_cast<size_t>(consensus::MAX_OUTBOUND_PEERS);

    if (current_outbound >= target) return;

    size_t needed = target - current_outbound;
    size_t attempts = 0;
    static constexpr size_t MAX_ATTEMPTS = 50;

    // Track subnets of current outbound peers
    std::map<uint16_t, int> subnet_count;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& [id, peer] : peers_) {
            if (peer->state() == PeerState::DISCONNECTED) continue;
            if (peer->is_inbound()) continue;
            subnet_count[peer->get_subnet_id()]++;
        }
    }

    for (size_t i = 0; i < needed && attempts < MAX_ATTEMPTS; ++attempts) {
        // Alternate between tried and new tables
        CNetAddr candidate;
        if (attempts % 3 == 0) {
            candidate = addrman_.select_from_new();
        } else {
            candidate = addrman_.select();
        }

        if (candidate.port == 0) {
            // No candidates available
            if (current_outbound == 0 && i == 0) {
                connect_seeds();
            }
            break;
        }

        // Skip banned addresses
        if (banman_.is_banned(candidate)) continue;

        // Skip already-connected addresses
        bool already_connected = false;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (const auto& [id, peer] : peers_) {
                if (peer->addr() == candidate &&
                    peer->state() != PeerState::DISCONNECTED) {
                    already_connected = true;
                    break;
                }
            }
        }
        if (already_connected) continue;

        // Enforce subnet diversity: max 2 outbound per /16
        uint16_t subnet = 0;
        if (candidate.is_ipv4()) {
            subnet = static_cast<uint16_t>((candidate.ip[12] << 8) | candidate.ip[13]);
        } else {
            subnet = static_cast<uint16_t>((candidate.ip[0] << 8) | candidate.ip[1]);
        }

        if (subnet_count[subnet] >= 2) continue;

        // Attempt connection
        connect_to(candidate);
        subnet_count[subnet]++;
        ++i;
    }
}

// ===========================================================================
// Inbound connection handling with eviction
// ===========================================================================

void NetManager::on_new_inbound(uv_stream_t* server) {
    // Check ban and connection limits before accepting
    if (inbound_count() >= static_cast<size_t>(consensus::MAX_INBOUND_PEERS)) {
        // Try to evict a low-quality inbound peer
        Peer* victim = select_eviction_candidate();
        if (victim) {
            LogInfo("net", "evicting peer %lu (%s) for new inbound",
                    (unsigned long)victim->id(),
                    victim->addr().to_string().c_str());
            disconnect(*victim, "evicted for new inbound");
        } else {
            // Cannot evict anyone -- reject the connection
            auto* client = new uv_tcp_t;
            uv_tcp_init(loop_, client);
            if (uv_accept(server, reinterpret_cast<uv_stream_t*>(client)) == 0) {
                uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
            } else {
                delete client;
            }
            LogError("net", "rejected inbound (at capacity, no eviction candidates)");
            return;
        }
    }

    auto* client = new uv_tcp_t;
    uv_tcp_init(loop_, client);

    if (uv_accept(server, reinterpret_cast<uv_stream_t*>(client)) != 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
        return;
    }

    // Extract remote address
    struct sockaddr_storage addr_storage;
    int namelen = sizeof(addr_storage);
    uv_tcp_getpeername(client, reinterpret_cast<struct sockaddr*>(&addr_storage), &namelen);

    CNetAddr remote_addr;
    if (addr_storage.ss_family == AF_INET) {
        auto* addr4 = reinterpret_cast<struct sockaddr_in*>(&addr_storage);
        std::memset(remote_addr.ip, 0, 10);
        remote_addr.ip[10] = 0xff;
        remote_addr.ip[11] = 0xff;
        std::memcpy(&remote_addr.ip[12], &addr4->sin_addr.s_addr, 4);
        remote_addr.port = ntohs(addr4->sin_port);
    } else if (addr_storage.ss_family == AF_INET6) {
        auto* addr6 = reinterpret_cast<struct sockaddr_in6*>(&addr_storage);
        std::memcpy(remote_addr.ip, &addr6->sin6_addr, 16);
        remote_addr.port = ntohs(addr6->sin6_port);
    }

    // Check ban list
    if (banman_.is_banned(remote_addr)) {
        LogError("net", "rejected banned inbound from %s",
                remote_addr.to_string().c_str());
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
        return;
    }

    // Check for duplicate connections from same IP
    int same_ip_count = 0;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& [id, peer] : peers_) {
            if (peer->state() == PeerState::DISCONNECTED) continue;
            if (std::memcmp(peer->addr().ip, remote_addr.ip, 16) == 0) {
                same_ip_count++;
            }
        }
    }

    // Allow at most 3 connections from the same IP
    if (same_ip_count >= 3) {
        LogError("net", "rejected inbound from %s (too many connections from same IP)",
                remote_addr.to_string().c_str());
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
        return;
    }

    LogInfo("net", "accepted inbound connection from %s",
            remote_addr.to_string().c_str());

    Peer& peer = create_peer(remote_addr, true, client);
    uv_read_start(reinterpret_cast<uv_stream_t*>(client), on_alloc, on_read);

    (void)peer;
}

// ===========================================================================
// Bandwidth management
// ===========================================================================

NetManager::BandwidthStats NetManager::get_bandwidth_stats() const {
    BandwidthStats stats;
    stats.total_sent = static_cast<int64_t>(total_bytes_sent_.load());
    stats.total_received = static_cast<int64_t>(total_bytes_recv_.load());
    stats.uptime_seconds = running_.load() ? GetTime() - start_time_ : 0;

    // Compute current rates from per-peer data
    double total_send_rate = 0.0;
    double total_recv_rate = 0.0;

    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& [id, peer] : peers_) {
            if (peer->state() == PeerState::DISCONNECTED) continue;
            total_send_rate += peer->send_bandwidth();
            total_recv_rate += peer->recv_bandwidth();
        }
    }

    stats.send_rate_kbps = total_send_rate / 1024.0;
    stats.recv_rate_kbps = total_recv_rate / 1024.0;

    return stats;
}

void NetManager::set_max_upload_rate(int64_t bytes_per_second) {
    max_upload_rate_ = bytes_per_second;
    LogInfo("net", "upload rate limit set to %ld bytes/s", (long)bytes_per_second);
}

bool NetManager::can_send(size_t bytes) const {
    if (max_upload_rate_ <= 0) return true;  // No limit

    // Simple token-bucket style rate limiting
    // Check if the current send rate is below the limit
    double current_rate = 0.0;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& [id, peer] : peers_) {
            if (peer->state() == PeerState::DISCONNECTED) continue;
            current_rate += peer->send_bandwidth();
        }
    }

    return current_rate + static_cast<double>(bytes) < static_cast<double>(max_upload_rate_);
}

// ===========================================================================
// Network event processing
// ===========================================================================

void NetManager::process_events() {
    if (!running_.load()) return;

    int64_t now = GetTime();

    // 1. Accept new connections (handled by libuv callbacks)
    // 2. Read from all peers (handled by libuv callbacks)
    // 3. Process complete messages (handled by process_recv)

    // 4. Check for handshake timeouts
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto& [id, peer] : peers_) {
            if (peer->state() == PeerState::DISCONNECTED) continue;

            // Disconnect peers stuck in handshake for over 60 seconds
            if (peer->state() != PeerState::HANDSHAKE_DONE &&
                now - peer->connect_time() > 60) {
                disconnect(*peer, "handshake timeout");
                continue;
            }

            // Disconnect peers that haven't sent anything in 20 minutes
            if (peer->state() == PeerState::HANDSHAKE_DONE &&
                peer->last_recv_time() > 0 &&
                now - peer->last_recv_time() > 1200) {
                disconnect(*peer, "no messages for 20 minutes");
                continue;
            }

            // Ban check
            if (peer->should_ban() && peer->state() != PeerState::DISCONNECTED) {
                banman_.ban(peer->addr());
                disconnect(*peer, "misbehavior threshold exceeded");
                continue;
            }
        }
    }

    // 5. Maintain outbound connections
    maintain_outbound_connections();

    // 6. Feeler connections (every 2 minutes)
    if (now - last_feeler_time_ >= 120) {
        last_feeler_time_ = now;
        start_feeler();
    }

    // 7. Peer rotation
    rotate_idle_peers(now);

    // 8. DNS seed resolution (initially and every 11 minutes if few peers)
    if (last_dns_seed_time_ == 0 ||
        (now - last_dns_seed_time_ >= 660 && addrman_.size() < 100)) {
        last_dns_seed_time_ = now;
        resolve_dns_seeds();
    }

    // 9. Bandwidth tracking
    update_peer_bandwidth(now);

    // 10. Clean up disconnected peers
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        std::vector<uint64_t> to_remove;
        for (auto& [id, peer] : peers_) {
            if (peer->state() == PeerState::DISCONNECTED &&
                now - peer->connect_time() > 60) {
                to_remove.push_back(id);
            }
        }
        for (uint64_t id : to_remove) {
            peers_.erase(id);
        }
    }

    // 11. Sweep expired bans (every 5 minutes)
    if (now - last_cleanup_time_ >= 300) {
        last_cleanup_time_ = now;
        banman_.sweep();
        addrman_.cleanup();
    }

    // 12. Save peers.dat periodically (every 15 minutes)
    if (now - last_peers_save_time_ >= 900) {
        last_peers_save_time_ = now;
        save_peers();
    }

    // 13. Message handler periodic maintenance
    handler_.on_tick();
}

// ===========================================================================
// Network thread function
// ===========================================================================

void NetManager::network_thread_func() {
    LogInfo("net", "network thread started");

    // Initialize libuv loop
    if (!start()) {
        LogError("net", "failed to start network");
        return;
    }

    start_time_ = GetTime();

    // Run the event loop
    run();

    LogInfo("net", "network thread exited");
}

// ===========================================================================
// Connection quality scoring for eviction
// ===========================================================================

int NetManager::compute_eviction_score(const Peer& peer) const {
    int score = 0;

    // Penalize high latency
    int64_t latency = peer.ping_latency_us();
    if (latency > 0) {
        if (latency > 5'000'000) score -= 20;       // > 5s
        else if (latency > 1'000'000) score -= 10;  // > 1s
        else if (latency > 500'000) score -= 5;     // > 500ms
        else score += 5;                              // Good latency
    }

    // Reward long-lived connections
    int64_t connected_for = GetTime() - peer.connect_time();
    if (connected_for > 86400) score += 20;       // > 24h
    else if (connected_for > 3600) score += 10;   // > 1h
    else if (connected_for > 300) score += 5;     // > 5min

    // Reward peers with high block height
    if (peer.start_height() > 0) {
        uint64_t our_height = chain_.height();
        if (peer.start_height() >= our_height) {
            score += 15;
        } else if (peer.start_height() >= our_height - 10) {
            score += 10;
        }
    }

    // Reward peers that relay compact blocks
    if (peer.supports_compact_blocks()) score += 5;

    // Penalize peers with high misbehavior score
    if (peer.misbehavior_score() > 50) score -= 30;
    else if (peer.misbehavior_score() > 20) score -= 15;
    else if (peer.misbehavior_score() > 0) score -= 5;

    // Reward active peers (recent messages)
    int64_t last_active = peer.last_recv_time();
    if (last_active > 0) {
        int64_t idle_time = GetTime() - last_active;
        if (idle_time < 60) score += 10;        // Active in last minute
        else if (idle_time < 300) score += 5;   // Active in last 5 min
        else if (idle_time > 600) score -= 10;  // Idle > 10 min
    }

    // Reward unique subnets
    uint16_t subnet = peer.get_subnet_id();
    int same_subnet = 0;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& [id, p] : peers_) {
            if (p->id() == peer.id()) continue;
            if (p->state() == PeerState::DISCONNECTED) continue;
            if (p->is_inbound() && p->get_subnet_id() == subnet) {
                same_subnet++;
            }
        }
    }
    if (same_subnet == 0) score += 10;  // Only peer from this subnet

    return score;
}

// ===========================================================================
// Advanced eviction with protection groups
// ===========================================================================

Peer* NetManager::select_eviction_candidate_advanced() {
    std::vector<std::pair<Peer*, int>> scored_candidates;

    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto& [id, peer] : peers_) {
            if (!peer->is_inbound()) continue;
            if (peer->state() != PeerState::HANDSHAKE_DONE) continue;
            scored_candidates.emplace_back(peer.get(), compute_eviction_score(*peer));
        }
    }

    if (scored_candidates.size() <= 8) return nullptr;

    // Sort by score (ascending -- lowest score = worst peer = first to evict)
    std::sort(scored_candidates.begin(), scored_candidates.end(),
              [](const auto& a, const auto& b) {
                  return a.second < b.second;
              });

    // Protect the top half
    size_t protect_count = scored_candidates.size() / 2;
    protect_count = std::min(protect_count, static_cast<size_t>(16));

    // Additionally protect peers from unique subnets
    std::set<uint16_t> protected_subnets;
    size_t protected_count = 0;

    // Protect from the high-score end
    for (size_t i = scored_candidates.size(); i > 0 && protected_count < protect_count; --i) {
        auto* peer = scored_candidates[i - 1].first;
        protected_subnets.insert(peer->get_subnet_id());
        protected_count++;
    }

    // Protect 4 peers with lowest latency
    std::vector<std::pair<Peer*, int64_t>> by_latency;
    for (auto& [peer, score] : scored_candidates) {
        if (peer->ping_latency_us() > 0) {
            by_latency.emplace_back(peer, peer->ping_latency_us());
        }
    }
    std::sort(by_latency.begin(), by_latency.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });

    std::set<uint64_t> protected_ids;
    for (size_t i = 0; i < std::min(by_latency.size(), static_cast<size_t>(4)); ++i) {
        protected_ids.insert(by_latency[i].first->id());
    }

    // Protect 4 peers with longest connection time
    std::vector<std::pair<Peer*, int64_t>> by_uptime;
    for (auto& [peer, score] : scored_candidates) {
        by_uptime.emplace_back(peer, GetTime() - peer->connect_time());
    }
    std::sort(by_uptime.begin(), by_uptime.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    for (size_t i = 0; i < std::min(by_uptime.size(), static_cast<size_t>(4)); ++i) {
        protected_ids.insert(by_uptime[i].first->id());
    }

    // Find the first unprotected candidate (lowest score)
    for (auto& [peer, score] : scored_candidates) {
        if (protected_ids.count(peer->id())) continue;
        return peer;
    }

    // All are protected -- return the absolute worst
    return scored_candidates.front().first;
}

// ===========================================================================
// Network statistics for RPC
// ===========================================================================

NetManager::NetworkInfo NetManager::get_network_info() const {
    NetworkInfo info;
    info.protocol_version = consensus::PROTOCOL_VERSION;
    info.connections = peer_count();
    info.connections_in = inbound_count();
    info.connections_out = outbound_count();
    info.total_bytes_sent = total_bytes_sent_.load();
    info.total_bytes_recv = total_bytes_recv_.load();

    auto bw = get_bandwidth_stats();
    info.send_rate = bw.send_rate_kbps;
    info.recv_rate = bw.recv_rate_kbps;
    info.uptime = bw.uptime_seconds;

    info.known_addresses = addrman_.size();
    info.banned_count = banman_.count();

    return info;
}

void NetManager::save_peers(const std::string& path) {
    (void)path;
    // AddrMan serialization would go here
}

} // namespace flow

