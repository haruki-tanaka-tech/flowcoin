// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "net/net.h"
#include "chain/chainstate.h"
#include "consensus/params.h"
#include "hash/keccak.h"
#include "util/random.h"
#include "util/time.h"

#include "uv.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace flow {

// ===========================================================================
// Seed nodes
// ===========================================================================

const std::vector<std::pair<std::string, uint16_t>> NetManager::SEED_NODES = {
    {"seed1.flowcoin.org", consensus::MAINNET_PORT},
    {"seed2.flowcoin.org", consensus::MAINNET_PORT},
    {"seed3.flowcoin.org", consensus::MAINNET_PORT},
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
        fprintf(stderr, "net: failed to create event loop\n");
        return false;
    }

    // Store NetManager pointer in loop data so callbacks can find us
    loop_->data = this;

    // Create and initialize the TCP server handle
    server_ = new uv_tcp_t;
    uv_tcp_init(loop_, server_);
    server_->data = this;

    // Bind to all interfaces
    struct sockaddr_in bind_addr;
    uv_ip4_addr("0.0.0.0", port_, &bind_addr);
    int r = uv_tcp_bind(server_, reinterpret_cast<const struct sockaddr*>(&bind_addr), 0);
    if (r < 0) {
        fprintf(stderr, "net: bind failed on port %u: %s\n", port_, uv_strerror(r));
        delete server_;
        server_ = nullptr;
        uv_loop_delete(loop_);
        loop_ = nullptr;
        return false;
    }

    // Start listening
    r = uv_listen(reinterpret_cast<uv_stream_t*>(server_), 128, on_new_connection);
    if (r < 0) {
        fprintf(stderr, "net: listen failed: %s\n", uv_strerror(r));
        uv_close(reinterpret_cast<uv_handle_t*>(server_), on_close);
        server_ = nullptr;
        uv_loop_delete(loop_);
        loop_ = nullptr;
        return false;
    }

    fprintf(stderr, "net: listening on port %u\n", port_);

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

    // Add seed nodes to address manager
    for (const auto& [ip, p] : SEED_NODES) {
        addrman_.add(CNetAddr(ip, p), GetTime());
    }

    return true;
}

void NetManager::stop() {
    if (!running_.load()) return;
    running_.store(false);

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

    // Don't connect if we already have too many outbound peers
    if (outbound_count() >= static_cast<size_t>(consensus::MAX_OUTBOUND_PEERS)) {
        return;
    }

    // Don't connect to ourselves or to peers we're already connected to
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& [id, peer] : peers_) {
            if (peer->addr() == addr && peer->state() != PeerState::DISCONNECTED) {
                return;  // already connected
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
        // For IPv6, we would use sockaddr_in6; skip for now as seeds are IPv4
        char ip6_str[INET6_ADDRSTRLEN];
        struct in6_addr addr6;
        std::memcpy(&addr6, addr.ip, 16);
        inet_ntop(AF_INET6, &addr6, ip6_str, sizeof(ip6_str));
        // Fall back to treating as IPv4 if mapped
        if (addr.is_ipv4()) {
            char ip_str[16];
            std::snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                          addr.ip[12], addr.ip[13], addr.ip[14], addr.ip[15]);
            uv_ip4_addr(ip_str, addr.port, &dest);
        } else {
            delete ctx;
            uv_close(reinterpret_cast<uv_handle_t*>(tcp), on_close);
            return;
        }
    }

    addrman_.mark_failed(addr);  // pre-mark as tried; mark_good on success

    int r = uv_tcp_connect(&ctx->req, tcp,
                           reinterpret_cast<const struct sockaddr*>(&dest),
                           on_connect);
    if (r < 0) {
        fprintf(stderr, "net: connect to %s failed: %s\n",
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
        fprintf(stderr, "net: write to peer %lu failed: %s\n",
                (unsigned long)peer.id(), uv_strerror(r));
        delete ctx;
        return;
    }

    peer.add_bytes_sent(data.size());
}

void NetManager::disconnect(Peer& peer, const std::string& reason) {
    if (peer.state() == PeerState::DISCONNECTED) return;

    fprintf(stderr, "net: disconnecting peer %lu (%s): %s\n",
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

size_t NetManager::peer_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    size_t count = 0;
    for (const auto& [id, peer] : peers_) {
        if (peer->state() != PeerState::DISCONNECTED) {
            count++;
        }
    }
    return count;
}

size_t NetManager::outbound_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    size_t count = 0;
    for (const auto& [id, peer] : peers_) {
        if (!peer->is_inbound() && peer->state() != PeerState::DISCONNECTED) {
            count++;
        }
    }
    return count;
}

size_t NetManager::inbound_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    size_t count = 0;
    for (const auto& [id, peer] : peers_) {
        if (peer->is_inbound() && peer->state() != PeerState::DISCONNECTED) {
            count++;
        }
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
        fprintf(stderr, "net: new connection error: %s\n", uv_strerror(status));
        return;
    }

    // Check if we have room for inbound peers
    if (self->inbound_count() >= static_cast<size_t>(consensus::MAX_INBOUND_PEERS)) {
        // Reject the connection by accepting and immediately closing
        auto* client = new uv_tcp_t;
        uv_tcp_init(self->loop_, client);
        if (uv_accept(server, reinterpret_cast<uv_stream_t*>(client)) == 0) {
            uv_close(reinterpret_cast<uv_handle_t*>(client), on_close);
        } else {
            delete client;
        }
        return;
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

    fprintf(stderr, "net: inbound connection from %s\n",
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
        fprintf(stderr, "net: outbound connect to %s failed: %s\n",
                ctx->addr.to_string().c_str(), uv_strerror(status));
        self->addrman_.mark_failed(ctx->addr);
        uv_close(reinterpret_cast<uv_handle_t*>(ctx->tcp_handle), on_close);
        delete ctx;
        return;
    }

    fprintf(stderr, "net: connected to %s\n", ctx->addr.to_string().c_str());

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
            fprintf(stderr, "net: read error on peer %lu: %s\n",
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

    // Append received data to the peer's buffer and process messages
    {
        std::lock_guard<std::mutex> lock(self->peers_mutex_);
        auto it = self->peers_.find(peer_id);
        if (it != self->peers_.end()) {
            Peer& peer = *it->second;
            peer.recv_buffer().insert(peer.recv_buffer().end(),
                                      buf->base, buf->base + nread);
            peer.add_bytes_recv(static_cast<uint64_t>(nread));
            self->process_recv(peer);

            // Check if peer should be banned
            if (peer.should_ban()) {
                self->disconnect(peer, "misbehavior ban");
            }
        }
    }

    delete[] buf->base;
}

void NetManager::on_write(uv_write_t* req, int status) {
    auto* ctx = static_cast<WriteContext*>(req->data);
    if (status < 0) {
        fprintf(stderr, "net: write error: %s\n", uv_strerror(status));
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
            fprintf(stderr, "net: bad magic from peer %lu (got 0x%08x, expected 0x%08x)\n",
                    (unsigned long)peer.id(), hdr.magic, magic_);
            peer.add_misbehavior(50);
            buf.clear();
            return;
        }

        // Validate payload size
        if (hdr.payload_size > MessageHeader::MAX_PAYLOAD_SIZE) {
            fprintf(stderr, "net: oversized payload from peer %lu: %u bytes\n",
                    (unsigned long)peer.id(), hdr.payload_size);
            peer.add_misbehavior(50);
            buf.clear();
            return;
        }

        // Check if we have the complete message (header + payload)
        size_t total_size = MessageHeader::SIZE + hdr.payload_size;
        if (buf.size() < total_size) {
            break;  // wait for more data
        }

        // Verify checksum
        const uint8_t* payload_ptr = buf.data() + MessageHeader::SIZE;
        uint32_t expected_checksum = compute_checksum(payload_ptr, hdr.payload_size);
        if (hdr.checksum != expected_checksum) {
            fprintf(stderr, "net: bad checksum from peer %lu on '%s'\n",
                    (unsigned long)peer.id(), hdr.command_string().c_str());
            peer.add_misbehavior(10);
            // Skip this message
            buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(total_size));
            continue;
        }

        // Extract command string
        std::string command = hdr.command_string();

        // Dispatch to message handler
        handler_.process_message(peer, command, payload_ptr, hdr.payload_size);

        // Remove the processed message from the buffer
        buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(total_size));
    }

    // Safety: if the buffer is growing too large without producing valid messages,
    // disconnect the peer to prevent memory exhaustion
    if (buf.size() > 4 * 1024 * 1024) {
        fprintf(stderr, "net: recv buffer overflow for peer %lu (%zu bytes)\n",
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

            // Disconnect peers that haven't responded in 20 minutes
            if (peer->last_recv_time() > 0 && now - peer->last_recv_time() > 1200) {
                disconnect(*peer, "ping timeout");
            }

            // Disconnect peers stuck in handshake for over 60 seconds
            if (peer->state() != PeerState::HANDSHAKE_DONE &&
                peer->state() != PeerState::DISCONNECTED &&
                now - peer->connect_time() > 60) {
                disconnect(*peer, "handshake timeout");
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

    // Try to maintain outbound connections
    maintain_connections();
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

    // Try to connect to addresses from the address manager
    for (size_t i = 0; i < needed; ++i) {
        CNetAddr addr = addrman_.select();
        if (addr.port == 0) {
            // No candidates available; try seeds if we have no connections at all
            if (current_outbound == 0 && i == 0) {
                connect_seeds();
            }
            break;
        }
        connect_to(addr);
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

} // namespace flow
