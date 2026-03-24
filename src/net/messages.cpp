// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "net/messages.h"
#include "net/net.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "consensus/params.h"
#include "hash/keccak.h"
#include "util/serialize.h"
#include "util/time.h"
#include "util/random.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace flow {

// ===========================================================================
// Construction
// ===========================================================================

MessageHandler::MessageHandler(ChainState& chain, NetManager& netman)
    : chain_(chain)
    , netman_(netman)
{
}

// ===========================================================================
// Message dispatch
// ===========================================================================

void MessageHandler::process_message(Peer& peer, const std::string& command,
                                     const uint8_t* payload, size_t payload_len) {
    peer.set_last_recv_time(GetTime());
    peer.inc_messages_recv();

    // Before handshake, only accept version and verack
    if (peer.state() != PeerState::HANDSHAKE_DONE) {
        if (command != NetCmd::VERSION && command != NetCmd::VERACK) {
            // Silently ignore pre-handshake messages
            return;
        }
    }

    if (command == NetCmd::VERSION) {
        handle_version(peer, payload, payload_len);
    } else if (command == NetCmd::VERACK) {
        handle_verack(peer);
    } else if (command == NetCmd::PING) {
        handle_ping(peer, payload, payload_len);
    } else if (command == NetCmd::PONG) {
        handle_pong(peer, payload, payload_len);
    } else if (command == NetCmd::GETADDR) {
        handle_getaddr(peer);
    } else if (command == NetCmd::ADDR) {
        handle_addr(peer, payload, payload_len);
    } else if (command == NetCmd::INV) {
        handle_inv(peer, payload, payload_len);
    } else if (command == NetCmd::GETDATA) {
        handle_getdata(peer, payload, payload_len);
    } else if (command == NetCmd::BLOCK) {
        handle_block(peer, payload, payload_len);
    } else if (command == NetCmd::TX) {
        handle_tx(peer, payload, payload_len);
    } else if (command == NetCmd::GETBLOCKS) {
        handle_getblocks(peer, payload, payload_len);
    } else if (command == NetCmd::GETHEADERS) {
        handle_getheaders(peer, payload, payload_len);
    } else if (command == NetCmd::HEADERS) {
        handle_headers(peer, payload, payload_len);
    } else {
        // Unknown command -- ignore
        fprintf(stderr, "net: unknown command '%s' from peer %lu\n",
                command.c_str(), (unsigned long)peer.id());
    }
}

// ===========================================================================
// Send helpers
// ===========================================================================

void MessageHandler::send(Peer& peer, const std::string& command,
                          const std::vector<uint8_t>& payload) {
    auto msg = build_message(consensus::MAINNET_MAGIC, command, payload);
    netman_.send_to(peer, msg);
    peer.set_last_send_time(GetTime());
    peer.inc_messages_sent();
}

void MessageHandler::send(Peer& peer, const std::string& command) {
    std::vector<uint8_t> empty;
    send(peer, command, empty);
}

// ===========================================================================
// Version / handshake
// ===========================================================================

void MessageHandler::send_version(Peer& peer) {
    VersionMessage ver;
    ver.protocol_version = consensus::PROTOCOL_VERSION;
    ver.services = NODE_NETWORK;
    ver.timestamp = GetTime();
    ver.addr_recv = peer.addr();
    ver.addr_from = CNetAddr("0.0.0.0", 0);
    ver.nonce = netman_.local_nonce();
    ver.user_agent = "/FlowCoin:1.0.0/";
    ver.start_height = chain_.height();

    send(peer, NetCmd::VERSION, ver.serialize());
    peer.set_version_sent(true);
    peer.set_state(PeerState::VERSION_SENT);
}

void MessageHandler::handle_version(Peer& peer, const uint8_t* data, size_t len) {
    if (peer.version_received()) {
        // Duplicate version message
        peer.add_misbehavior(10);
        return;
    }

    VersionMessage ver;
    if (!VersionMessage::deserialize(data, len, ver)) {
        fprintf(stderr, "net: failed to parse version from peer %lu\n",
                (unsigned long)peer.id());
        peer.add_misbehavior(10);
        return;
    }

    // Self-connection detection
    if (ver.nonce == netman_.local_nonce()) {
        fprintf(stderr, "net: detected self-connection to peer %lu, disconnecting\n",
                (unsigned long)peer.id());
        netman_.disconnect(peer, "self-connection");
        return;
    }

    // Store peer info
    peer.set_version(ver.protocol_version);
    peer.set_services(ver.services);
    peer.set_start_height(ver.start_height);
    peer.set_user_agent(ver.user_agent);
    peer.set_nonce(ver.nonce);
    peer.set_version_received(true);

    fprintf(stderr, "net: received version from peer %lu: %s height=%lu\n",
            (unsigned long)peer.id(), ver.user_agent.c_str(),
            (unsigned long)ver.start_height);

    // Send verack to acknowledge their version
    send(peer, NetCmd::VERACK);

    // If this is an inbound connection, we haven't sent our version yet
    if (peer.is_inbound() && !peer.version_sent()) {
        send_version(peer);
    }

    // If we've already received their verack, handshake is done
    if (peer.verack_received()) {
        peer.set_state(PeerState::HANDSHAKE_DONE);
        netman_.addrman().mark_good(peer.addr());
        fprintf(stderr, "net: handshake complete with peer %lu (%s)\n",
                (unsigned long)peer.id(), peer.addr().to_string().c_str());
    }
}

void MessageHandler::handle_verack(Peer& peer) {
    if (peer.verack_received()) {
        peer.add_misbehavior(10);
        return;
    }

    peer.set_verack_received(true);

    // Handshake is complete once we have both version and verack
    if (peer.version_received()) {
        peer.set_state(PeerState::HANDSHAKE_DONE);
        netman_.addrman().mark_good(peer.addr());
        fprintf(stderr, "net: handshake complete with peer %lu (%s)\n",
                (unsigned long)peer.id(), peer.addr().to_string().c_str());

        // If peer has a higher chain, request headers
        uint64_t our_height = chain_.height();
        uint64_t their_height = peer.start_height();
        if (their_height > our_height) {
            fprintf(stderr, "net: peer %lu has height %lu (ours: %lu), requesting headers\n",
                    (unsigned long)peer.id(), (unsigned long)their_height,
                    (unsigned long)our_height);

            // Send getheaders with our tip as the locator
            DataWriter w;
            // Protocol version
            w.write_u32_le(consensus::PROTOCOL_VERSION);
            // Locator hash count
            w.write_compact_size(1);
            // Our tip hash
            CBlockIndex* tip = chain_.tip();
            if (tip) {
                w.write_bytes(tip->hash.data(), 32);
            } else {
                uint256 zero;
                w.write_bytes(zero.data(), 32);
            }
            // Hash stop (zero = get as many as possible)
            uint256 zero_stop;
            w.write_bytes(zero_stop.data(), 32);

            send(peer, NetCmd::GETHEADERS, w.release());
        }

        // Ask for their address list
        send(peer, NetCmd::GETADDR);
    }
}

// ===========================================================================
// Ping / pong
// ===========================================================================

void MessageHandler::handle_ping(Peer& peer, const uint8_t* data, size_t len) {
    if (len < 8) {
        peer.add_misbehavior(10);
        return;
    }

    // Echo the 8-byte nonce back as a pong
    DataWriter w;
    w.write_bytes(data, 8);
    send(peer, NetCmd::PONG, w.release());
}

void MessageHandler::handle_pong(Peer& peer, const uint8_t* data, size_t len) {
    if (len < 8) return;

    DataReader r(data, len);
    uint64_t nonce = r.read_u64_le();

    if (nonce == peer.ping_nonce() && peer.ping_nonce() != 0) {
        int64_t now = GetTimeMicros();
        int64_t latency = now - peer.last_ping_time();
        peer.set_ping_latency_us(latency);
        peer.set_ping_nonce(0);
    }
}

// ===========================================================================
// Address relay
// ===========================================================================

void MessageHandler::handle_getaddr(Peer& peer) {
    auto addrs = netman_.addrman().get_addresses(
        static_cast<size_t>(consensus::ADDR_RELAY_MAX));

    if (addrs.empty()) return;

    DataWriter w;
    w.write_compact_size(addrs.size());
    for (const auto& addr : addrs) {
        // Timestamp (4 bytes for addr messages, like Bitcoin)
        w.write_u32_le(static_cast<uint32_t>(GetTime()));
        // Services
        w.write_u64_le(NODE_NETWORK);
        // Address
        addr.serialize(w);
    }
    send(peer, NetCmd::ADDR, w.release());
}

void MessageHandler::handle_addr(Peer& peer, const uint8_t* data, size_t len) {
    DataReader r(data, len);
    uint64_t count = r.read_compact_size();
    if (r.error()) return;

    if (count > static_cast<uint64_t>(consensus::ADDR_RELAY_MAX)) {
        peer.add_misbehavior(20);
        return;
    }

    int64_t now = GetTime();
    for (uint64_t i = 0; i < count; ++i) {
        uint32_t ts = r.read_u32_le();
        /*uint64_t services =*/ r.read_u64_le();
        CNetAddr addr = CNetAddr::deserialize(r);
        if (r.error()) break;

        // Ignore addresses older than 3 hours
        if (static_cast<int64_t>(ts) < now - 3 * 3600) continue;

        // Ignore addresses with port 0
        if (addr.port == 0) continue;

        netman_.addrman().add(addr, static_cast<int64_t>(ts));
    }
}

// ===========================================================================
// Inventory
// ===========================================================================

void MessageHandler::write_inv_item(DataWriter& w, const InvItem& item) {
    w.write_u32_le(static_cast<uint32_t>(item.type));
    w.write_bytes(item.hash.data(), 32);
}

std::vector<InvItem> MessageHandler::read_inv_items(const uint8_t* data, size_t len) {
    std::vector<InvItem> items;
    DataReader r(data, len);
    uint64_t count = r.read_compact_size();
    if (r.error()) return items;

    if (count > static_cast<uint64_t>(consensus::MAX_INV_SIZE)) return items;

    items.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        InvItem item;
        item.type = static_cast<InvType>(r.read_u32_le());
        auto hash_bytes = r.read_bytes(32);
        if (r.error()) break;
        std::memcpy(item.hash.data(), hash_bytes.data(), 32);
        items.push_back(item);
    }
    return items;
}

// Forward declarations of block serialization helpers
static std::vector<uint8_t> serialize_block_for_wire(const CBlock& block);
static bool deserialize_block_from_wire(const uint8_t* data, size_t len, CBlock& block);

void MessageHandler::handle_inv(Peer& peer, const uint8_t* data, size_t len) {
    auto items = read_inv_items(data, len);
    if (items.empty()) return;

    // Collect items we don't have and request them
    std::vector<InvItem> needed;
    for (const auto& item : items) {
        if (item.type == INV_BLOCK) {
            if (!chain_.block_tree().find(item.hash)) {
                needed.push_back(item);
            }
        } else if (item.type == INV_TX) {
            // We don't have a mempool yet, so request all txs
            needed.push_back(item);
        }
    }

    if (needed.empty()) return;

    // Send getdata for the items we need
    DataWriter w;
    w.write_compact_size(needed.size());
    for (const auto& item : needed) {
        write_inv_item(w, item);
    }
    send(peer, NetCmd::GETDATA, w.release());
}

void MessageHandler::handle_getdata(Peer& peer, const uint8_t* data, size_t len) {
    auto items = read_inv_items(data, len);
    if (items.empty()) return;

    for (const auto& item : items) {
        if (item.type == INV_BLOCK) {
            CBlockIndex* index = chain_.block_tree().find(item.hash);
            if (!index || index->pos.is_null()) {
                // Send notfound
                DataWriter w;
                w.write_compact_size(1);
                write_inv_item(w, item);
                send(peer, NetCmd::NOTFOUND, w.release());
                continue;
            }

            // Read block from disk and send it
            CBlock block;
            if (chain_.block_store().read_block(index->pos, block)) {
                // Serialize the full block
                auto block_data = serialize_block_for_wire(block);
                send(peer, NetCmd::BLOCK, block_data);
            } else {
                DataWriter w;
                w.write_compact_size(1);
                write_inv_item(w, item);
                send(peer, NetCmd::NOTFOUND, w.release());
            }
        } else if (item.type == INV_TX) {
            // No mempool yet -- send notfound
            DataWriter w;
            w.write_compact_size(1);
            write_inv_item(w, item);
            send(peer, NetCmd::NOTFOUND, w.release());
        }
    }
}

// ===========================================================================
// Block / transaction messages
// ===========================================================================

// Serialize a full block for the wire protocol.
// Layout: header (unsigned data + sig) + varint(tx_count) + txs + delta_payload
static std::vector<uint8_t> serialize_block_for_wire(const CBlock& block) {
    DataWriter w(4096);

    // Write the full header (244 bytes unsigned + 64 bytes sig = 308 bytes)
    auto unsigned_data = block.get_unsigned_data();
    w.write_bytes(unsigned_data.data(), unsigned_data.size());
    w.write_bytes(block.miner_sig.data(), 64);

    // Transaction count
    w.write_compact_size(block.vtx.size());

    // Transactions
    for (const auto& tx : block.vtx) {
        auto tx_data = tx.serialize();
        w.write_bytes(tx_data.data(), tx_data.size());
    }

    // Delta payload length + data
    w.write_compact_size(block.delta_payload.size());
    if (!block.delta_payload.empty()) {
        w.write_bytes(block.delta_payload.data(), block.delta_payload.size());
    }

    return w.release();
}

// Deserialize a block from wire data
static bool deserialize_block_from_wire(const uint8_t* data, size_t len, CBlock& block) {
    DataReader r(data, len);

    // Read the 244-byte unsigned header
    // prev_hash (32)
    auto prev_hash_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.prev_hash.data(), prev_hash_bytes.data(), 32);

    // merkle_root (32)
    auto merkle_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.merkle_root.data(), merkle_bytes.data(), 32);

    // training_hash (32)
    auto training_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.training_hash.data(), training_bytes.data(), 32);

    // dataset_hash (32)
    auto dataset_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.dataset_hash.data(), dataset_bytes.data(), 32);

    // height (8)
    block.height = r.read_u64_le();
    // timestamp (8)
    block.timestamp = r.read_i64_le();
    // nbits (4)
    block.nbits = r.read_u32_le();
    // val_loss (4)
    block.val_loss = r.read_float_le();
    // prev_val_loss (4)
    block.prev_val_loss = r.read_float_le();
    // d_model (4)
    block.d_model = r.read_u32_le();
    // n_layers (4)
    block.n_layers = r.read_u32_le();
    // d_ff (4)
    block.d_ff = r.read_u32_le();
    // n_heads (4)
    block.n_heads = r.read_u32_le();
    // gru_dim (4)
    block.gru_dim = r.read_u32_le();
    // n_slots (4)
    block.n_slots = r.read_u32_le();
    // train_steps (4)
    block.train_steps = r.read_u32_le();
    // stagnation (4)
    block.stagnation = r.read_u32_le();
    // delta_offset (4)
    block.delta_offset = r.read_u32_le();
    // delta_length (4)
    block.delta_length = r.read_u32_le();
    // sparse_count (4)
    block.sparse_count = r.read_u32_le();
    // sparse_threshold (4)
    block.sparse_threshold = r.read_float_le();
    // nonce (4)
    block.nonce = r.read_u32_le();
    // version (4)
    block.version = r.read_u32_le();
    // miner_pubkey (32)
    auto pubkey_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.miner_pubkey.data(), pubkey_bytes.data(), 32);
    // miner_sig (64)
    auto sig_bytes = r.read_bytes(64);
    if (r.error()) return false;
    std::memcpy(block.miner_sig.data(), sig_bytes.data(), 64);

    // Transaction count
    uint64_t tx_count = r.read_compact_size();
    if (r.error() || tx_count > 100000) return false;

    // Deserialize transactions
    // Each transaction is self-describing via its serialize() format:
    // version(4) + varint(vin_count) + inputs + varint(vout_count) + outputs + locktime(8)
    block.vtx.resize(static_cast<size_t>(tx_count));
    for (uint64_t i = 0; i < tx_count; ++i) {
        CTransaction& tx = block.vtx[i];

        tx.version = r.read_u32_le();

        uint64_t vin_count = r.read_compact_size();
        if (r.error() || vin_count > 10000) return false;

        tx.vin.resize(static_cast<size_t>(vin_count));
        for (uint64_t j = 0; j < vin_count; ++j) {
            auto txid_bytes = r.read_bytes(32);
            if (r.error()) return false;
            std::memcpy(tx.vin[j].prevout.txid.data(), txid_bytes.data(), 32);
            tx.vin[j].prevout.index = r.read_u32_le();
            auto pk_bytes = r.read_bytes(32);
            if (r.error()) return false;
            std::memcpy(tx.vin[j].pubkey.data(), pk_bytes.data(), 32);
            auto sig_b = r.read_bytes(64);
            if (r.error()) return false;
            std::memcpy(tx.vin[j].signature.data(), sig_b.data(), 64);
        }

        uint64_t vout_count = r.read_compact_size();
        if (r.error() || vout_count > 10000) return false;

        tx.vout.resize(static_cast<size_t>(vout_count));
        for (uint64_t j = 0; j < vout_count; ++j) {
            tx.vout[j].amount = r.read_i64_le();
            auto pkh_bytes = r.read_bytes(32);
            if (r.error()) return false;
            std::memcpy(tx.vout[j].pubkey_hash.data(), pkh_bytes.data(), 32);
        }

        tx.locktime = r.read_i64_le();
        if (r.error()) return false;
    }

    // Delta payload
    uint64_t delta_len = r.read_compact_size();
    if (r.error()) return false;
    if (delta_len > consensus::MAX_DELTA_SIZE) return false;

    if (delta_len > 0) {
        auto delta_bytes = r.read_bytes(static_cast<size_t>(delta_len));
        if (r.error()) return false;
        block.delta_payload = std::move(delta_bytes);
    }

    return true;
}

void MessageHandler::handle_block(Peer& peer, const uint8_t* data, size_t len) {
    CBlock block;
    if (!deserialize_block_from_wire(data, len, block)) {
        fprintf(stderr, "net: failed to deserialize block from peer %lu\n",
                (unsigned long)peer.id());
        peer.add_misbehavior(20);
        return;
    }

    uint256 block_hash = block.get_hash();

    // Check if we already have this block
    if (chain_.block_tree().find(block_hash)) {
        return;  // already have it
    }

    // Validate and accept the block
    consensus::ValidationState vstate;
    if (chain_.accept_block(block, vstate)) {
        fprintf(stderr, "net: accepted block at height %lu from peer %lu\n",
                (unsigned long)block.height, (unsigned long)peer.id());
        relay_block(block_hash);
    } else {
        fprintf(stderr, "net: rejected block from peer %lu: %s\n",
                (unsigned long)peer.id(), vstate.reject_reason().c_str());
        peer.add_misbehavior(10);
    }
}

void MessageHandler::handle_tx(Peer& peer, const uint8_t* data, size_t len) {
    (void)data;
    (void)len;
    // No mempool implemented yet -- silently accept and discard
    // In future: deserialize CTransaction, validate, add to mempool, relay
    fprintf(stderr, "net: received tx from peer %lu (mempool not implemented)\n",
            (unsigned long)peer.id());
}

// ===========================================================================
// Block header sync (getheaders / headers)
// ===========================================================================

CBlockIndex* MessageHandler::find_fork_point(const std::vector<uint256>& locator_hashes) {
    // Walk the locator hashes and find the first one we know about
    for (const auto& hash : locator_hashes) {
        CBlockIndex* index = chain_.block_tree().find(hash);
        if (index && (index->status & BLOCK_HEADER_VALID)) {
            return index;
        }
    }
    // If no match, return genesis
    return chain_.block_tree().genesis();
}

void MessageHandler::write_block_header(DataWriter& w, const CBlockHeader& hdr) {
    auto unsigned_data = hdr.get_unsigned_data();
    w.write_bytes(unsigned_data.data(), unsigned_data.size());
    w.write_bytes(hdr.miner_sig.data(), 64);
}

void MessageHandler::handle_getheaders(Peer& peer, const uint8_t* data, size_t len) {
    DataReader r(data, len);

    /*uint32_t version =*/ r.read_u32_le();
    uint64_t locator_count = r.read_compact_size();
    if (r.error() || locator_count > 101) {
        peer.add_misbehavior(20);
        return;
    }

    std::vector<uint256> locator_hashes;
    locator_hashes.reserve(static_cast<size_t>(locator_count));
    for (uint64_t i = 0; i < locator_count; ++i) {
        auto hash_bytes = r.read_bytes(32);
        if (r.error()) return;
        uint256 hash;
        std::memcpy(hash.data(), hash_bytes.data(), 32);
        locator_hashes.push_back(hash);
    }

    uint256 hash_stop;
    auto stop_bytes = r.read_bytes(32);
    if (r.error()) return;
    std::memcpy(hash_stop.data(), stop_bytes.data(), 32);

    // Find the fork point
    CBlockIndex* fork = find_fork_point(locator_hashes);
    if (!fork) fork = chain_.block_tree().genesis();

    // Walk forward from fork, collecting up to 2000 headers
    CBlockIndex* tip = chain_.tip();
    if (!tip) return;

    // Build the chain from tip back to fork
    std::vector<CBlockIndex*> chain_path;
    CBlockIndex* current = tip;
    while (current && current != fork) {
        chain_path.push_back(current);
        current = current->prev;
    }
    std::reverse(chain_path.begin(), chain_path.end());

    constexpr size_t MAX_HEADERS = 2000;
    size_t limit = std::min(chain_path.size(), MAX_HEADERS);

    // First pass: serialize headers into a buffer, counting how many succeed
    size_t actual_count = 0;
    DataWriter headers_buf;
    for (size_t i = 0; i < limit; ++i) {
        CBlockIndex* idx = chain_path[i];
        CBlock blk;
        if (idx->pos.is_null() || !chain_.block_store().read_block(idx->pos, blk)) {
            break;
        }
        write_block_header(headers_buf, blk);
        actual_count++;
        if (!hash_stop.is_null() && idx->hash == hash_stop) {
            break;
        }
    }

    if (actual_count > 0) {
        DataWriter final_w;
        final_w.write_compact_size(actual_count);
        final_w.write_bytes(headers_buf.data().data(), headers_buf.data().size());
        send(peer, NetCmd::HEADERS, final_w.release());
    }
}

void MessageHandler::handle_headers(Peer& peer, const uint8_t* data, size_t len) {
    DataReader r(data, len);

    uint64_t count = r.read_compact_size();
    if (r.error() || count > 2000) {
        peer.add_misbehavior(20);
        return;
    }

    bool got_new = false;
    for (uint64_t i = 0; i < count; ++i) {
        // Each header is 308 bytes (244 unsigned + 64 sig)
        CBlockHeader hdr;

        // Read the unsigned portion field by field
        auto prev_hash_bytes = r.read_bytes(32);
        if (r.error()) return;
        std::memcpy(hdr.prev_hash.data(), prev_hash_bytes.data(), 32);

        auto merkle_bytes = r.read_bytes(32);
        if (r.error()) return;
        std::memcpy(hdr.merkle_root.data(), merkle_bytes.data(), 32);

        auto training_bytes = r.read_bytes(32);
        if (r.error()) return;
        std::memcpy(hdr.training_hash.data(), training_bytes.data(), 32);

        auto dataset_bytes = r.read_bytes(32);
        if (r.error()) return;
        std::memcpy(hdr.dataset_hash.data(), dataset_bytes.data(), 32);

        hdr.height = r.read_u64_le();
        hdr.timestamp = r.read_i64_le();
        hdr.nbits = r.read_u32_le();
        hdr.val_loss = r.read_float_le();
        hdr.prev_val_loss = r.read_float_le();
        hdr.d_model = r.read_u32_le();
        hdr.n_layers = r.read_u32_le();
        hdr.d_ff = r.read_u32_le();
        hdr.n_heads = r.read_u32_le();
        hdr.gru_dim = r.read_u32_le();
        hdr.n_slots = r.read_u32_le();
        hdr.train_steps = r.read_u32_le();
        hdr.stagnation = r.read_u32_le();
        hdr.delta_offset = r.read_u32_le();
        hdr.delta_length = r.read_u32_le();
        hdr.sparse_count = r.read_u32_le();
        hdr.sparse_threshold = r.read_float_le();
        hdr.nonce = r.read_u32_le();
        hdr.version = r.read_u32_le();

        auto pubkey_bytes = r.read_bytes(32);
        if (r.error()) return;
        std::memcpy(hdr.miner_pubkey.data(), pubkey_bytes.data(), 32);

        auto sig_bytes = r.read_bytes(64);
        if (r.error()) return;
        std::memcpy(hdr.miner_sig.data(), sig_bytes.data(), 64);

        // Try to accept the header
        uint256 hdr_hash = hdr.get_hash();
        if (chain_.block_tree().find(hdr_hash)) {
            continue;  // already have it
        }

        consensus::ValidationState vstate;
        CBlockIndex* new_idx = chain_.accept_header(hdr, vstate);
        if (new_idx) {
            got_new = true;
        } else {
            fprintf(stderr, "net: rejected header from peer %lu: %s\n",
                    (unsigned long)peer.id(), vstate.reject_reason().c_str());
            peer.add_misbehavior(10);
            return;
        }
    }

    // If we received a full batch (2000), there may be more
    if (count == 2000 && got_new) {
        // Request more headers starting from our new tip
        DataWriter w;
        w.write_u32_le(consensus::PROTOCOL_VERSION);
        w.write_compact_size(1);
        CBlockIndex* tip = chain_.tip();
        if (tip) {
            w.write_bytes(tip->hash.data(), 32);
        } else {
            uint256 zero;
            w.write_bytes(zero.data(), 32);
        }
        uint256 zero_stop;
        w.write_bytes(zero_stop.data(), 32);
        send(peer, NetCmd::GETHEADERS, w.release());
    }
}

// ===========================================================================
// getblocks
// ===========================================================================

void MessageHandler::handle_getblocks(Peer& peer, const uint8_t* data, size_t len) {
    DataReader r(data, len);

    /*uint32_t version =*/ r.read_u32_le();
    uint64_t locator_count = r.read_compact_size();
    if (r.error() || locator_count > 101) {
        peer.add_misbehavior(20);
        return;
    }

    std::vector<uint256> locator_hashes;
    locator_hashes.reserve(static_cast<size_t>(locator_count));
    for (uint64_t i = 0; i < locator_count; ++i) {
        auto hash_bytes = r.read_bytes(32);
        if (r.error()) return;
        uint256 hash;
        std::memcpy(hash.data(), hash_bytes.data(), 32);
        locator_hashes.push_back(hash);
    }

    uint256 hash_stop;
    auto stop_bytes = r.read_bytes(32);
    if (r.error()) return;
    std::memcpy(hash_stop.data(), stop_bytes.data(), 32);

    CBlockIndex* fork = find_fork_point(locator_hashes);
    if (!fork) fork = chain_.block_tree().genesis();

    CBlockIndex* tip = chain_.tip();
    if (!tip) return;

    // Build chain from fork to tip
    std::vector<CBlockIndex*> chain_path;
    CBlockIndex* current = tip;
    while (current && current != fork) {
        chain_path.push_back(current);
        current = current->prev;
    }
    std::reverse(chain_path.begin(), chain_path.end());

    // Send INV for up to 500 blocks
    constexpr size_t MAX_INV_BLOCKS = 500;
    size_t count = std::min(chain_path.size(), MAX_INV_BLOCKS);

    if (count == 0) return;

    DataWriter w;
    std::vector<InvItem> inv_items;
    for (size_t i = 0; i < count; ++i) {
        InvItem item;
        item.type = INV_BLOCK;
        item.hash = chain_path[i]->hash;
        inv_items.push_back(item);

        if (!hash_stop.is_null() && chain_path[i]->hash == hash_stop) {
            break;
        }
    }

    w.write_compact_size(inv_items.size());
    for (const auto& item : inv_items) {
        write_inv_item(w, item);
    }
    send(peer, NetCmd::INV, w.release());
}

// ===========================================================================
// Relay
// ===========================================================================

void MessageHandler::relay_block(const uint256& hash) {
    DataWriter w;
    w.write_compact_size(1);
    InvItem item;
    item.type = INV_BLOCK;
    item.hash = hash;
    write_inv_item(w, item);

    netman_.broadcast(NetCmd::INV, w.release());
}

void MessageHandler::relay_tx(const uint256& txid) {
    DataWriter w;
    w.write_compact_size(1);
    InvItem item;
    item.type = INV_TX;
    item.hash = txid;
    write_inv_item(w, item);

    netman_.broadcast(NetCmd::INV, w.release());
}

} // namespace flow
