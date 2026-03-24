// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "net/messages.h"
#include "net/net.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "consensus/params.h"
#include "hash/keccak.h"
#include "util/serialize.h"
#include "util/strencodings.h"
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
    } else if (command == NetCmd::REJECT) {
        handle_reject(peer, payload, payload_len);
    } else if (command == NetCmd::SENDHEADERS) {
        handle_sendheaders(peer);
    } else if (command == NetCmd::SENDCMPCT) {
        handle_sendcmpct(peer, payload, payload_len);
    } else if (command == NetCmd::CMPCTBLOCK) {
        handle_cmpctblock(peer, payload, payload_len);
    } else if (command == NetCmd::GETBLOCKTXN) {
        handle_getblocktxn(peer, payload, payload_len);
    } else if (command == NetCmd::BLOCKTXN) {
        handle_blocktxn(peer, payload, payload_len);
    } else if (command == NetCmd::FEEFILTER) {
        handle_feefilter(peer, payload, payload_len);
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

// ===========================================================================
// reject message — log and update misbehavior
// ===========================================================================

void MessageHandler::handle_reject(Peer& peer, const uint8_t* data, size_t len) {
    DataReader r(data, len);

    // Rejected message type (compact size string)
    uint64_t msg_len = r.read_compact_size();
    if (r.error() || msg_len > 12) {
        peer.add_misbehavior(5);
        return;
    }
    auto msg_bytes = r.read_bytes(static_cast<size_t>(msg_len));
    if (r.error()) return;
    std::string rejected_msg(reinterpret_cast<const char*>(msg_bytes.data()),
                             msg_bytes.size());

    // Rejection code
    uint8_t code = r.read_u8();
    if (r.error()) return;

    // Reason string
    uint64_t reason_len = r.read_compact_size();
    if (r.error() || reason_len > 256) return;
    std::string reason;
    if (reason_len > 0) {
        auto reason_bytes = r.read_bytes(static_cast<size_t>(reason_len));
        if (r.error()) return;
        reason.assign(reinterpret_cast<const char*>(reason_bytes.data()),
                      reason_bytes.size());
    }

    // Optional: 32-byte hash of the rejected data (for blocks/txs)
    uint256 rejected_hash;
    if (r.remaining() >= 32) {
        auto hash_bytes = r.read_bytes(32);
        if (!r.error()) {
            std::memcpy(rejected_hash.data(), hash_bytes.data(), 32);
        }
    }

    const char* code_str = "unknown";
    switch (code) {
        case 0x01: code_str = "REJECT_MALFORMED"; break;
        case 0x10: code_str = "REJECT_INVALID"; break;
        case 0x11: code_str = "REJECT_OBSOLETE"; break;
        case 0x12: code_str = "REJECT_DUPLICATE"; break;
        case 0x40: code_str = "REJECT_NONSTANDARD"; break;
        case 0x41: code_str = "REJECT_DUST"; break;
        case 0x42: code_str = "REJECT_INSUFFICIENTFEE"; break;
        case 0x43: code_str = "REJECT_CHECKPOINT"; break;
        default: break;
    }

    fprintf(stderr, "net: peer %lu rejected %s: %s (code=%s, hash=%.8s...)\n",
            (unsigned long)peer.id(),
            rejected_msg.c_str(),
            reason.c_str(),
            code_str,
            hex_encode(rejected_hash.data(), 32).c_str());

    // Update misbehavior score based on the rejection
    // Rejecting our blocks or txs might indicate protocol incompatibility
    // but isn't necessarily malicious. Only penalize for certain codes.
    if (code == 0x01 || code == 0x10) {
        // Malformed or invalid from their perspective -- minor penalty
        peer.add_misbehavior(1);
    }
}

// ===========================================================================
// sendheaders — peer wants headers-first announcements
// ===========================================================================

void MessageHandler::handle_sendheaders(Peer& peer) {
    peer.set_prefers_headers(true);
    fprintf(stderr, "net: peer %lu prefers header announcements\n",
            (unsigned long)peer.id());
}

// ===========================================================================
// sendcmpct — enable compact block relay
// ===========================================================================

void MessageHandler::handle_sendcmpct(Peer& peer, const uint8_t* data, size_t len) {
    if (len < 9) {
        peer.add_misbehavior(5);
        return;
    }

    DataReader r(data, len);

    // announce (bool): whether to use high-bandwidth mode
    uint8_t announce = r.read_u8();
    // version (uint64_t): compact block protocol version
    uint64_t version = r.read_u64_le();

    if (r.error()) {
        peer.add_misbehavior(5);
        return;
    }

    // We support compact block version 1
    if (version == 1) {
        peer.set_supports_compact_blocks(true);
        peer.set_compact_block_version(version);
        peer.set_wants_cmpct_high_bandwidth(announce != 0);
        peer.set_prefers_compact_blocks(announce != 0);

        fprintf(stderr, "net: peer %lu supports compact blocks v%lu (high-bw: %s)\n",
                (unsigned long)peer.id(),
                (unsigned long)version,
                announce ? "yes" : "no");
    }
}

// ===========================================================================
// Compact block short txid computation
// ===========================================================================

uint64_t MessageHandler::compute_short_txid(const uint256& txid,
                                             uint64_t nonce,
                                             const uint256& block_hash) {
    // SipHash-style short ID: hash(block_hash || nonce || txid) and take 6 bytes
    DataWriter w(80);
    w.write_bytes(block_hash.data(), 32);
    w.write_u64_le(nonce);
    w.write_bytes(txid.data(), 32);

    uint256 h = keccak256(w.data().data(), w.data().size());
    uint64_t result = 0;
    std::memcpy(&result, h.data(), 6);
    return result & 0xFFFFFFFFFFFFULL;  // Mask to 6 bytes (48 bits)
}

// ===========================================================================
// cmpctblock — receive a compact block
// ===========================================================================

void MessageHandler::handle_cmpctblock(Peer& peer, const uint8_t* data, size_t len) {
    DataReader r(data, len);

    // Read the block header (same format as in headers message)
    CBlockHeader hdr;

    auto prev_hash_bytes = r.read_bytes(32);
    if (r.error()) { peer.add_misbehavior(10); return; }
    std::memcpy(hdr.prev_hash.data(), prev_hash_bytes.data(), 32);

    auto merkle_bytes = r.read_bytes(32);
    if (r.error()) { peer.add_misbehavior(10); return; }
    std::memcpy(hdr.merkle_root.data(), merkle_bytes.data(), 32);

    auto training_bytes = r.read_bytes(32);
    if (r.error()) { peer.add_misbehavior(10); return; }
    std::memcpy(hdr.training_hash.data(), training_bytes.data(), 32);

    auto dataset_bytes = r.read_bytes(32);
    if (r.error()) { peer.add_misbehavior(10); return; }
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
    if (r.error()) { peer.add_misbehavior(10); return; }
    std::memcpy(hdr.miner_pubkey.data(), pubkey_bytes.data(), 32);

    auto sig_bytes = r.read_bytes(64);
    if (r.error()) { peer.add_misbehavior(10); return; }
    std::memcpy(hdr.miner_sig.data(), sig_bytes.data(), 64);

    // Nonce for short txid computation
    uint64_t cmpct_nonce = r.read_u64_le();
    if (r.error()) { peer.add_misbehavior(10); return; }

    uint256 block_hash = hdr.get_hash();

    // Check if we already have this block
    if (chain_.block_tree().find(block_hash)) {
        return;
    }

    // Read short transaction IDs
    uint64_t short_id_count = r.read_compact_size();
    if (r.error() || short_id_count > 100000) {
        peer.add_misbehavior(20);
        return;
    }

    std::vector<uint64_t> short_ids;
    short_ids.reserve(static_cast<size_t>(short_id_count));
    for (uint64_t i = 0; i < short_id_count; i++) {
        // Each short ID is 6 bytes
        auto id_bytes = r.read_bytes(6);
        if (r.error()) { peer.add_misbehavior(10); return; }
        uint64_t short_id = 0;
        std::memcpy(&short_id, id_bytes.data(), 6);
        short_ids.push_back(short_id);
    }

    // Read prefilled transactions
    uint64_t prefilled_count = r.read_compact_size();
    if (r.error() || prefilled_count > short_id_count + 1) {
        peer.add_misbehavior(20);
        return;
    }

    std::vector<uint32_t> prefilled_indices;
    std::vector<CTransaction> prefilled_txs;
    prefilled_indices.reserve(static_cast<size_t>(prefilled_count));
    prefilled_txs.reserve(static_cast<size_t>(prefilled_count));

    for (uint64_t i = 0; i < prefilled_count; i++) {
        uint64_t diff_index = r.read_compact_size();
        if (r.error()) { peer.add_misbehavior(10); return; }

        // Deserialize the transaction
        CTransaction tx;
        tx.version = r.read_u32_le();
        uint64_t vin_count = r.read_compact_size();
        if (r.error() || vin_count > 10000) { peer.add_misbehavior(10); return; }

        tx.vin.resize(static_cast<size_t>(vin_count));
        for (uint64_t j = 0; j < vin_count; j++) {
            auto txid_bytes = r.read_bytes(32);
            if (r.error()) return;
            std::memcpy(tx.vin[j].prevout.txid.data(), txid_bytes.data(), 32);
            tx.vin[j].prevout.index = r.read_u32_le();
            auto pk_bytes = r.read_bytes(32);
            if (r.error()) return;
            std::memcpy(tx.vin[j].pubkey.data(), pk_bytes.data(), 32);
            auto sig_b = r.read_bytes(64);
            if (r.error()) return;
            std::memcpy(tx.vin[j].signature.data(), sig_b.data(), 64);
        }

        uint64_t vout_count = r.read_compact_size();
        if (r.error() || vout_count > 10000) { peer.add_misbehavior(10); return; }

        tx.vout.resize(static_cast<size_t>(vout_count));
        for (uint64_t j = 0; j < vout_count; j++) {
            tx.vout[j].amount = r.read_i64_le();
            auto pkh_bytes = r.read_bytes(32);
            if (r.error()) return;
            std::memcpy(tx.vout[j].pubkey_hash.data(), pkh_bytes.data(), 32);
        }

        tx.locktime = r.read_i64_le();
        if (r.error()) return;

        prefilled_indices.push_back(static_cast<uint32_t>(diff_index));
        prefilled_txs.push_back(std::move(tx));
    }

    // Store the compact block state for reconstruction
    CompactBlockState& cbs = compact_states_[peer.id()];
    cbs.block_hash = block_hash;
    cbs.header = hdr;
    cbs.short_txids = std::move(short_ids);
    cbs.prefilled_txs = std::move(prefilled_txs);
    cbs.prefilled_indices = std::move(prefilled_indices);
    cbs.waiting_for_txns = false;

    // Attempt reconstruction from mempool
    // Build the expected transaction list
    size_t total_tx = cbs.short_txids.size() + cbs.prefilled_indices.size();
    cbs.reconstructed_txs.resize(total_tx);

    // Place prefilled transactions
    uint32_t last_idx = 0;
    for (size_t i = 0; i < cbs.prefilled_indices.size(); i++) {
        uint32_t actual_idx = last_idx + cbs.prefilled_indices[i];
        if (actual_idx >= total_tx) {
            peer.add_misbehavior(20);
            compact_states_.erase(peer.id());
            return;
        }
        cbs.reconstructed_txs[actual_idx] = cbs.prefilled_txs[i];
        last_idx = actual_idx + 1;
    }

    // For now, since we don't have a full mempool, we need to request
    // all missing transactions via getblocktxn.
    // In a full implementation, we'd match short_txids against the mempool.

    std::vector<uint32_t> missing_indices;
    uint32_t short_idx = 0;
    for (uint32_t i = 0; i < total_tx; i++) {
        // Check if this position is prefilled
        bool is_prefilled = false;
        uint32_t check_idx = 0;
        for (size_t p = 0; p < cbs.prefilled_indices.size(); p++) {
            check_idx += cbs.prefilled_indices[p];
            if (p > 0) check_idx++;
            if (check_idx == i) {
                is_prefilled = true;
                break;
            }
        }
        if (!is_prefilled) {
            missing_indices.push_back(i);
            short_idx++;
        }
    }

    if (missing_indices.empty()) {
        // All transactions are available. Reconstruct the full block.
        CBlock block;
        // Copy header fields
        block.prev_hash = cbs.header.prev_hash;
        block.merkle_root = cbs.header.merkle_root;
        block.training_hash = cbs.header.training_hash;
        block.dataset_hash = cbs.header.dataset_hash;
        block.height = cbs.header.height;
        block.timestamp = cbs.header.timestamp;
        block.nbits = cbs.header.nbits;
        block.val_loss = cbs.header.val_loss;
        block.prev_val_loss = cbs.header.prev_val_loss;
        block.d_model = cbs.header.d_model;
        block.n_layers = cbs.header.n_layers;
        block.d_ff = cbs.header.d_ff;
        block.n_heads = cbs.header.n_heads;
        block.gru_dim = cbs.header.gru_dim;
        block.n_slots = cbs.header.n_slots;
        block.train_steps = cbs.header.train_steps;
        block.stagnation = cbs.header.stagnation;
        block.delta_offset = cbs.header.delta_offset;
        block.delta_length = cbs.header.delta_length;
        block.sparse_count = cbs.header.sparse_count;
        block.sparse_threshold = cbs.header.sparse_threshold;
        block.nonce = cbs.header.nonce;
        block.version = cbs.header.version;
        block.miner_pubkey = cbs.header.miner_pubkey;
        block.miner_sig = cbs.header.miner_sig;
        block.vtx = std::move(cbs.reconstructed_txs);

        compact_states_.erase(peer.id());

        consensus::ValidationState vstate;
        if (chain_.accept_block(block, vstate)) {
            fprintf(stderr, "net: accepted compact block at height %lu from peer %lu\n",
                    (unsigned long)block.height, (unsigned long)peer.id());
            relay_block(block_hash);
        } else {
            fprintf(stderr, "net: rejected compact block from peer %lu: %s\n",
                    (unsigned long)peer.id(), vstate.reject_reason().c_str());
            peer.add_misbehavior(10);
        }
    } else {
        // Request missing transactions
        cbs.waiting_for_txns = true;

        DataWriter w;
        w.write_bytes(block_hash.data(), 32);
        w.write_compact_size(missing_indices.size());
        for (uint32_t idx : missing_indices) {
            w.write_compact_size(idx);
        }
        send(peer, NetCmd::GETBLOCKTXN, w.release());

        fprintf(stderr, "net: compact block from peer %lu missing %zu txs, requesting\n",
                (unsigned long)peer.id(), missing_indices.size());
    }
}

// ===========================================================================
// getblocktxn — serve missing transactions for compact block
// ===========================================================================

void MessageHandler::handle_getblocktxn(Peer& peer, const uint8_t* data, size_t len) {
    DataReader r(data, len);

    auto hash_bytes = r.read_bytes(32);
    if (r.error()) { peer.add_misbehavior(10); return; }
    uint256 block_hash;
    std::memcpy(block_hash.data(), hash_bytes.data(), 32);

    uint64_t index_count = r.read_compact_size();
    if (r.error() || index_count > 100000) {
        peer.add_misbehavior(20);
        return;
    }

    std::vector<uint32_t> indices;
    indices.reserve(static_cast<size_t>(index_count));
    for (uint64_t i = 0; i < index_count; i++) {
        uint64_t idx = r.read_compact_size();
        if (r.error()) return;
        indices.push_back(static_cast<uint32_t>(idx));
    }

    // Find the block
    CBlockIndex* index = chain_.block_tree().find(block_hash);
    if (!index || index->pos.is_null()) {
        // We don't have this block — send nothing
        return;
    }

    CBlock block;
    if (!chain_.block_store().read_block(index->pos, block)) {
        return;
    }

    // Build response: blocktxn message
    DataWriter w;
    w.write_bytes(block_hash.data(), 32);
    w.write_compact_size(indices.size());

    for (uint32_t idx : indices) {
        if (idx >= block.vtx.size()) {
            peer.add_misbehavior(10);
            return;
        }
        auto tx_data = block.vtx[idx].serialize();
        w.write_bytes(tx_data.data(), tx_data.size());
    }

    send(peer, NetCmd::BLOCKTXN, w.release());
}

// ===========================================================================
// blocktxn — fill in missing txs for compact block reconstruction
// ===========================================================================

void MessageHandler::handle_blocktxn(Peer& peer, const uint8_t* data, size_t len) {
    DataReader r(data, len);

    auto hash_bytes = r.read_bytes(32);
    if (r.error()) { peer.add_misbehavior(10); return; }
    uint256 block_hash;
    std::memcpy(block_hash.data(), hash_bytes.data(), 32);

    // Find our compact block state for this peer
    auto it = compact_states_.find(peer.id());
    if (it == compact_states_.end() || it->second.block_hash != block_hash) {
        // We didn't request this or it's for a different block
        return;
    }

    CompactBlockState& cbs = it->second;

    // Read the transactions
    uint64_t tx_count = r.read_compact_size();
    if (r.error() || tx_count > 100000) {
        peer.add_misbehavior(20);
        compact_states_.erase(it);
        return;
    }

    std::vector<CTransaction> txns;
    txns.reserve(static_cast<size_t>(tx_count));

    for (uint64_t i = 0; i < tx_count; i++) {
        CTransaction tx;
        tx.version = r.read_u32_le();

        uint64_t vin_count = r.read_compact_size();
        if (r.error() || vin_count > 10000) {
            peer.add_misbehavior(10);
            compact_states_.erase(it);
            return;
        }

        tx.vin.resize(static_cast<size_t>(vin_count));
        for (uint64_t j = 0; j < vin_count; j++) {
            auto txid_bytes = r.read_bytes(32);
            if (r.error()) { compact_states_.erase(it); return; }
            std::memcpy(tx.vin[j].prevout.txid.data(), txid_bytes.data(), 32);
            tx.vin[j].prevout.index = r.read_u32_le();
            auto pk_bytes = r.read_bytes(32);
            if (r.error()) { compact_states_.erase(it); return; }
            std::memcpy(tx.vin[j].pubkey.data(), pk_bytes.data(), 32);
            auto sig_b = r.read_bytes(64);
            if (r.error()) { compact_states_.erase(it); return; }
            std::memcpy(tx.vin[j].signature.data(), sig_b.data(), 64);
        }

        uint64_t vout_count = r.read_compact_size();
        if (r.error() || vout_count > 10000) {
            peer.add_misbehavior(10);
            compact_states_.erase(it);
            return;
        }

        tx.vout.resize(static_cast<size_t>(vout_count));
        for (uint64_t j = 0; j < vout_count; j++) {
            tx.vout[j].amount = r.read_i64_le();
            auto pkh_bytes = r.read_bytes(32);
            if (r.error()) { compact_states_.erase(it); return; }
            std::memcpy(tx.vout[j].pubkey_hash.data(), pkh_bytes.data(), 32);
        }

        tx.locktime = r.read_i64_le();
        if (r.error()) { compact_states_.erase(it); return; }

        txns.push_back(std::move(tx));
    }

    // Fill in the missing positions
    size_t tx_idx = 0;
    for (size_t i = 0; i < cbs.reconstructed_txs.size() && tx_idx < txns.size(); i++) {
        // Check if this position was prefilled
        if (cbs.reconstructed_txs[i].vin.empty() && cbs.reconstructed_txs[i].vout.empty()) {
            cbs.reconstructed_txs[i] = std::move(txns[tx_idx]);
            tx_idx++;
        }
    }

    // Reconstruct the full block
    CBlock block;
    block.prev_hash = cbs.header.prev_hash;
    block.merkle_root = cbs.header.merkle_root;
    block.training_hash = cbs.header.training_hash;
    block.dataset_hash = cbs.header.dataset_hash;
    block.height = cbs.header.height;
    block.timestamp = cbs.header.timestamp;
    block.nbits = cbs.header.nbits;
    block.val_loss = cbs.header.val_loss;
    block.prev_val_loss = cbs.header.prev_val_loss;
    block.d_model = cbs.header.d_model;
    block.n_layers = cbs.header.n_layers;
    block.d_ff = cbs.header.d_ff;
    block.n_heads = cbs.header.n_heads;
    block.gru_dim = cbs.header.gru_dim;
    block.n_slots = cbs.header.n_slots;
    block.train_steps = cbs.header.train_steps;
    block.stagnation = cbs.header.stagnation;
    block.delta_offset = cbs.header.delta_offset;
    block.delta_length = cbs.header.delta_length;
    block.sparse_count = cbs.header.sparse_count;
    block.sparse_threshold = cbs.header.sparse_threshold;
    block.nonce = cbs.header.nonce;
    block.version = cbs.header.version;
    block.miner_pubkey = cbs.header.miner_pubkey;
    block.miner_sig = cbs.header.miner_sig;
    block.vtx = std::move(cbs.reconstructed_txs);

    compact_states_.erase(it);

    consensus::ValidationState vstate;
    if (chain_.accept_block(block, vstate)) {
        fprintf(stderr, "net: accepted reconstructed block at height %lu from peer %lu\n",
                (unsigned long)block.height, (unsigned long)peer.id());
        relay_block(block_hash);
    } else {
        fprintf(stderr, "net: rejected reconstructed block from peer %lu: %s\n",
                (unsigned long)peer.id(), vstate.reject_reason().c_str());
        peer.add_misbehavior(10);
    }
}

// ===========================================================================
// feefilter — set minimum fee rate for tx relay
// ===========================================================================

void MessageHandler::handle_feefilter(Peer& peer, const uint8_t* data, size_t len) {
    if (len < 8) {
        peer.add_misbehavior(5);
        return;
    }

    DataReader r(data, len);
    int64_t fee_rate = r.read_i64_le();
    if (r.error()) return;

    // Sanity check: fee rate should be non-negative and reasonable
    if (fee_rate < 0) {
        peer.add_misbehavior(10);
        return;
    }

    // Cap at 100 BTC/kB (clearly unreasonable, likely an attack)
    constexpr int64_t MAX_FEE_RATE = 10'000'000'000LL;
    if (fee_rate > MAX_FEE_RATE) {
        peer.add_misbehavior(10);
        return;
    }

    peer.set_fee_filter(fee_rate);
    fprintf(stderr, "net: peer %lu set fee filter to %ld sat/kB\n",
            (unsigned long)peer.id(), (long)fee_rate);
}

} // namespace flow

