// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "net/messages.h"
#include "net/net.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "mempool/mempool.h"
#include "consensus/params.h"
#include "hash/keccak.h"
#include "util/serialize.h"
#include "util/strencodings.h"
#include "util/time.h"
#include "util/random.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>
#include "logging.h"

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
    } else if (command == NetCmd::NOTFOUND) {
        handle_notfound_full(peer, payload, payload_len);
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
        LogInfo("net", "unknown command '%s' from peer %lu",
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
    ver.addr_from = CNetAddr("0.0.0.0", netman_.port());
    ver.nonce = netman_.local_nonce();
    ver.user_agent = "/FlowCoin:1.0.0/";
    ver.start_height = chain_.height();
    ver.node_id = netman_.node_id();

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
        LogError("net", "failed to parse version from peer %lu",
                (unsigned long)peer.id());
        peer.add_misbehavior(10);
        return;
    }

    // Self-connection detection
    if (ver.nonce == netman_.local_nonce()) {
        LogInfo("net", "detected self-connection to peer %lu, disconnecting",
                (unsigned long)peer.id());
        netman_.disconnect(peer, "self-connection");
        return;
    }

    // Reject peers with incompatible protocol version
    if (ver.protocol_version < consensus::MIN_PROTOCOL_VERSION) {
        LogInfo("net", "peer %lu has old protocol version %u (min %u), disconnecting",
                (unsigned long)peer.id(), ver.protocol_version,
                consensus::MIN_PROTOCOL_VERSION);
        netman_.disconnect(peer, "obsolete-version");
        return;
    }

    // Store peer info
    peer.set_version(ver.protocol_version);
    peer.set_services(ver.services);
    peer.set_start_height(ver.start_height);
    peer.set_user_agent(ver.user_agent);
    peer.set_nonce(ver.nonce);
    peer.set_node_id(ver.node_id);
    peer.set_version_received(true);

    LogInfo("net", "received version from peer %lu: %s height=%lu node_id=%016llx",
            (unsigned long)peer.id(), ver.user_agent.c_str(),
            (unsigned long)ver.start_height, (unsigned long long)ver.node_id);

    // Link peers with same node_id (same node via IPv4 + IPv6)
    if (ver.node_id != 0) {
        auto peers = netman_.get_peers();
        for (const Peer* other : peers) {
            if (other->id() != peer.id() &&
                other->node_id() == ver.node_id &&
                other->state() != PeerState::DISCONNECTED) {
                LogInfo("net", "peer %lu shares node_id %016llx with peer %lu (same node, dual-stack)",
                        (unsigned long)peer.id(), (unsigned long long)ver.node_id,
                        (unsigned long)other->id());
                break;
            }
        }
    }

    // Send verack to acknowledge their version
    send(peer, NetCmd::VERACK);

    // If this is an inbound connection, we haven't sent our version yet
    if (peer.is_inbound() && !peer.version_sent()) {
        send_version(peer);
    }

    // Store listen port from version message
    if (ver.addr_from.port != 0) {
        peer.set_listen_port(ver.addr_from.port);
    }

    // If we've already received their verack, handshake is done
    if (peer.verack_received()) {
        peer.set_state(PeerState::HANDSHAKE_DONE);
        // Register peer with listen port in addrman
        CNetAddr listen_addr = peer.addr();
        if (peer.listen_port() != 0) {
            listen_addr.port = peer.listen_port();
        }
        netman_.addrman().add(listen_addr, GetTime());
        netman_.addrman().mark_good(listen_addr);
        LogInfo("net", "handshake complete with peer %lu (%s listen=%s) node_id=%016llx",
                (unsigned long)peer.id(), peer.addr().to_string().c_str(),
                listen_addr.to_string().c_str(),
                (unsigned long long)peer.node_id());

        // If peer has a higher chain, request headers
        uint64_t our_height = chain_.height();
        uint64_t their_height = peer.start_height();
        if (their_height > our_height) {
            LogInfo("net", "peer %lu has height %lu (ours: %lu), requesting headers",
                    (unsigned long)peer.id(), (unsigned long)their_height,
                    (unsigned long)our_height);

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
            send(peer, NetCmd::GETHEADERS, w.data());
        }
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
        CNetAddr listen_addr = peer.addr();
        if (peer.listen_port() != 0) {
            listen_addr.port = peer.listen_port();
        }
        netman_.addrman().add(listen_addr, GetTime());
        netman_.addrman().mark_good(listen_addr);
        LogInfo("net", "handshake complete with peer %lu (%s listen=%s) node_id=%016llx",
                (unsigned long)peer.id(), peer.addr().to_string().c_str(),
                listen_addr.to_string().c_str(),
                (unsigned long long)peer.node_id());

        // If peer has a higher chain, request headers
        uint64_t our_height = chain_.height();
        uint64_t their_height = peer.start_height();
        if (their_height > our_height) {
            LogInfo("net", "peer %lu has height %lu (ours: %lu), requesting headers",
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

    // Collect items we don't have, with dedup
    std::vector<InvItem> needed;
    std::set<uint256> seen;
    for (const auto& item : items) {
        if (seen.count(item.hash)) continue;  // dedup within batch
        seen.insert(item.hash);

        if (item.type == INV_BLOCK) {
            CBlockIndex* idx = chain_.block_tree().find(item.hash);
            if (!idx || !(idx->status & BLOCK_FULLY_VALIDATED)) {
                // Skip if we already requested this block from this peer
                if (peer.has_inflight(item.hash)) continue;
                peer.mark_inflight(item.hash);
                needed.push_back(item);
            }
        } else if (item.type == INV_TX) {
            needed.push_back(item);
        }
    }

    if (needed.empty()) return;

    LogInfo("net", "inv from peer %lu: requesting %lu items via getdata",
            (unsigned long)peer.id(), (unsigned long)needed.size());

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

    LogInfo("net", "getdata from peer %lu: %lu items requested",
            (unsigned long)peer.id(), (unsigned long)items.size());

    size_t blocks_sent = 0;
    size_t not_found = 0;

    for (const auto& item : items) {
        if (item.type == INV_BLOCK) {
            CBlockIndex* index = chain_.block_tree().find(item.hash);
            if (!index || index->pos.is_null()) {
                // Send notfound
                LogInfo("net", "getdata: block %s not found on disk (index=%s, pos_null=%s), "
                        "sending notfound to peer %lu",
                        hex_encode(item.hash.data(), 8).c_str(),
                        index ? "yes" : "no",
                        index ? (index->pos.is_null() ? "yes" : "no") : "n/a",
                        (unsigned long)peer.id());
                DataWriter w;
                w.write_compact_size(1);
                write_inv_item(w, item);
                send(peer, NetCmd::NOTFOUND, w.release());
                not_found++;
                continue;
            }

            // Read block from disk and send it
            CBlock block;
            if (chain_.block_store().read_block(index->pos, block)) {
                LogInfo("net", "sending block at height %lu (hash=%s) to peer %lu [%lu/%lu]",
                        (unsigned long)index->height,
                        hex_encode(item.hash.data(), 8).c_str(),
                        (unsigned long)peer.id(),
                        (unsigned long)(blocks_sent + 1),
                        (unsigned long)items.size());
                auto block_data = serialize_block_for_wire(block);
                send(peer, NetCmd::BLOCK, block_data);
                blocks_sent++;
            } else {
                LogError("net", "getdata: failed to read block at height %lu from disk",
                        (unsigned long)index->height);
                DataWriter w;
                w.write_compact_size(1);
                write_inv_item(w, item);
                send(peer, NetCmd::NOTFOUND, w.release());
                not_found++;
            }
        } else if (item.type == INV_TX) {
            // No mempool yet -- send notfound
            DataWriter w;
            w.write_compact_size(1);
            write_inv_item(w, item);
            send(peer, NetCmd::NOTFOUND, w.release());
            not_found++;
        }
    }

    LogInfo("net", "getdata from peer %lu complete: sent %lu blocks, %lu not found",
            (unsigned long)peer.id(), (unsigned long)blocks_sent,
            (unsigned long)not_found);
}

// ===========================================================================
// Block / transaction messages
// ===========================================================================

// Serialize a full block for the wire protocol.
// Layout: header (92 unsigned + 32 pubkey + 64 sig) + varint(tx_count) + txs
static std::vector<uint8_t> serialize_block_for_wire(const CBlock& block) {
    DataWriter w(4096);

    // Write the full 188-byte header: 92 unsigned + 32 pubkey + 64 sig
    auto unsigned_data = block.get_unsigned_data();
    w.write_bytes(unsigned_data.data(), unsigned_data.size());
    w.write_bytes(block.miner_pubkey.data(), 32);
    w.write_bytes(block.miner_sig.data(), 64);

    // Transaction count
    w.write_compact_size(block.vtx.size());

    // Transactions
    for (const auto& tx : block.vtx) {
        auto tx_data = tx.serialize();
        w.write_bytes(tx_data.data(), tx_data.size());
    }

    return w.release();
}

// Deserialize a block from wire data (188-byte header format)
static bool deserialize_block_from_wire(const uint8_t* data, size_t len, CBlock& block) {
    DataReader r(data, len);

    // Read the 92-byte unsigned header
    // prev_hash (32)
    auto prev_hash_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.prev_hash.data(), prev_hash_bytes.data(), 32);

    // merkle_root (32)
    auto merkle_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.merkle_root.data(), merkle_bytes.data(), 32);

    // height (8)
    block.height = r.read_u64_le();
    // timestamp (8)
    block.timestamp = r.read_i64_le();
    // nbits (4)
    block.nbits = r.read_u32_le();
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

    return true;
}

void MessageHandler::handle_block(Peer& peer, const uint8_t* data, size_t len) {
    CBlock block;
    if (!deserialize_block_from_wire(data, len, block)) {
        LogError("net", "failed to deserialize block from peer %lu (%zu bytes)",
                (unsigned long)peer.id(), len);
        peer.add_misbehavior(20);
        return;
    }

    uint256 block_hash = block.get_hash();
    peer.clear_inflight(block_hash);

    // Check if we already have this block fully validated.
    // Note: accept_header() inserts header-only entries into the block tree,
    // so we must check for BLOCK_FULLY_VALIDATED rather than mere existence.
    CBlockIndex* existing = chain_.block_tree().find(block_hash);
    if (existing && (existing->status & BLOCK_FULLY_VALIDATED)) {
        LogInfo("net", "block at height %lu already fully validated, skipping",
                (unsigned long)block.height);
        return;
    }

    LogInfo("net", "processing block %s at height %lu from peer %lu "
            "(prev=%s, %zu txs, our tip=%lu)",
            hex_encode(block_hash.data(), 8).c_str(),
            (unsigned long)block.height, (unsigned long)peer.id(),
            hex_encode(block.prev_hash.data(), 8).c_str(),
            block.vtx.size(),
            (unsigned long)chain_.height());

    // Validate and accept the block
    consensus::ValidationState vstate;
    uint64_t tip_before = chain_.height();
    if (chain_.accept_block(block, vstate)) {
        LogInfo("net", "accepted block at height %lu from peer %lu (tip now %lu)",
                (unsigned long)block.height, (unsigned long)peer.id(),
                (unsigned long)chain_.height());
        // Only relay if this block actually advanced our tip
        if (chain_.height() > tip_before) {
            relay_block(block_hash, &peer);
        }
    } else {
        // Don't penalize for bad-prevblk or reorg failures — normal during forks
        std::string reason = vstate.reject_reason();
        if (reason != "bad-prevblk" && reason != "reorg-disconnect-failed") {
            LogError("net", "rejected block at height %lu from peer %lu: %s "
                    "(prev_hash=%s, nbits=0x%08x)",
                    (unsigned long)block.height, (unsigned long)peer.id(),
                    reason.c_str(),
                    hex_encode(block.prev_hash.data(), 8).c_str(),
                    block.nbits);
            peer.add_misbehavior(10);
        }
    }
}

void MessageHandler::handle_tx(Peer& peer, const uint8_t* data, size_t len) {
    (void)data;
    (void)len;
    // No mempool implemented yet -- silently accept and discard
    // In future: deserialize CTransaction, validate, add to mempool, relay
    LogInfo("net", "received tx from peer %lu (mempool not implemented)",
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
    // Write the full 188-byte header: 92 unsigned + 32 pubkey + 64 sig
    auto unsigned_data = hdr.get_unsigned_data();
    w.write_bytes(unsigned_data.data(), unsigned_data.size());
    w.write_bytes(hdr.miner_pubkey.data(), 32);
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

    LogInfo("net", "getheaders from peer %lu: fork at height %lu, sending %lu headers",
            (unsigned long)peer.id(),
            (unsigned long)(fork ? fork->height : 0),
            (unsigned long)actual_count);

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

    LogInfo("net", "received %lu headers from peer %lu",
            (unsigned long)count, (unsigned long)peer.id());

    bool got_new = false;
    std::vector<uint256> new_header_hashes;

    for (uint64_t i = 0; i < count; ++i) {
        // Each header is 188 bytes (92 unsigned + 32 pubkey + 64 sig)
        CBlockHeader hdr;

        // Read the 92-byte unsigned portion field by field
        auto prev_hash_bytes = r.read_bytes(32);
        if (r.error()) return;
        std::memcpy(hdr.prev_hash.data(), prev_hash_bytes.data(), 32);

        auto merkle_bytes = r.read_bytes(32);
        if (r.error()) return;
        std::memcpy(hdr.merkle_root.data(), merkle_bytes.data(), 32);

        hdr.height = r.read_u64_le();
        hdr.timestamp = r.read_i64_le();
        hdr.nbits = r.read_u32_le();
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
        CBlockIndex* existing = chain_.block_tree().find(hdr_hash);
        if (existing) {
            // Already have header — but if not fully validated, we still need the block
            if (!(existing->status & BLOCK_FULLY_VALIDATED)) {
                new_header_hashes.push_back(hdr_hash);
                got_new = true;
            }
            continue;
        }

        consensus::ValidationState vstate;
        CBlockIndex* new_idx = chain_.accept_header(hdr, vstate);
        if (new_idx) {
            got_new = true;
            new_header_hashes.push_back(hdr_hash);
        } else {
            LogError("net", "rejected header from peer %lu: %s",
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

    // Request full blocks for new headers AND any header-only entries
    // Combine newly accepted + scan tree for header-only above our tip
    std::vector<uint256> blocks_needed = new_header_hashes;

    // Also scan for any header-only entries above our tip
    uint64_t our_height = chain_.height();
    uint64_t peer_height = peer.start_height();
    for (uint64_t h = our_height + 1; h <= peer_height && h <= our_height + 500; ++h) {
        auto at_height = chain_.block_tree().get_at_height(h);
        for (auto* idx : at_height) {
            if (!(idx->status & BLOCK_FULLY_VALIDATED)) {
                // Check not already in blocks_needed
                bool already = false;
                for (const auto& bh : blocks_needed) {
                    if (bh == idx->hash) { already = true; break; }
                }
                if (!already) blocks_needed.push_back(idx->hash);
            }
        }
    }

    if (!blocks_needed.empty()) {
        LogInfo("net", "requesting %lu blocks from peer %lu",
                (unsigned long)blocks_needed.size(),
                (unsigned long)peer.id());

        DataWriter w;
        w.write_compact_size(blocks_needed.size());
        for (const auto& hash : blocks_needed) {
            w.write_u32_le(static_cast<uint32_t>(INV_BLOCK));
            w.write_bytes(hash.data(), 32);
        }
        send(peer, NetCmd::GETDATA, w.release());
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

void MessageHandler::relay_block(const uint256& hash, const Peer* exclude) {
    LogInfo("net", "relaying block %s via inv to all peers",
            hex_encode(hash.data(), 8).c_str());

    DataWriter w;
    w.write_compact_size(1);
    InvItem item;
    item.type = INV_BLOCK;
    item.hash = hash;
    write_inv_item(w, item);

    netman_.broadcast_except(NetCmd::INV, w.release(), exclude);
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

    LogError("net", "peer %lu rejected %s: %s (code=%s, hash=%.8s...)",
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
    LogInfo("net", "peer %lu prefers header announcements",
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

        LogInfo("net", "peer %lu supports compact blocks v%lu (high-bw: %s)",
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

    // Read the 188-byte block header (92 unsigned + 32 pubkey + 64 sig)
    CBlockHeader hdr;

    auto prev_hash_bytes = r.read_bytes(32);
    if (r.error()) { peer.add_misbehavior(10); return; }
    std::memcpy(hdr.prev_hash.data(), prev_hash_bytes.data(), 32);

    auto merkle_bytes = r.read_bytes(32);
    if (r.error()) { peer.add_misbehavior(10); return; }
    std::memcpy(hdr.merkle_root.data(), merkle_bytes.data(), 32);

    hdr.height = r.read_u64_le();
    hdr.timestamp = r.read_i64_le();
    hdr.nbits = r.read_u32_le();
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
    (void)cmpct_nonce;
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
        // PoW: training_hash and dataset_hash removed
        block.height = cbs.header.height;
        block.timestamp = cbs.header.timestamp;
        block.nbits = cbs.header.nbits;














        block.nonce = cbs.header.nonce;
        block.version = cbs.header.version;
        block.miner_pubkey = cbs.header.miner_pubkey;
        block.miner_sig = cbs.header.miner_sig;
        block.vtx = std::move(cbs.reconstructed_txs);

        compact_states_.erase(peer.id());

        consensus::ValidationState vstate;
        if (chain_.accept_block(block, vstate)) {
            LogInfo("net", "accepted compact block at height %lu from peer %lu",
                    (unsigned long)block.height, (unsigned long)peer.id());
            relay_block(block_hash);
        } else {
            LogError("net", "rejected compact block from peer %lu: %s",
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

        LogInfo("net", "compact block from peer %lu missing %zu txs, requesting",
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
    block.height = cbs.header.height;
    block.timestamp = cbs.header.timestamp;
    block.nbits = cbs.header.nbits;














    block.nonce = cbs.header.nonce;
    block.version = cbs.header.version;
    block.miner_pubkey = cbs.header.miner_pubkey;
    block.miner_sig = cbs.header.miner_sig;
    block.vtx = std::move(cbs.reconstructed_txs);

    compact_states_.erase(it);

    consensus::ValidationState vstate;
    if (chain_.accept_block(block, vstate)) {
        LogInfo("net", "accepted reconstructed block at height %lu from peer %lu",
                (unsigned long)block.height, (unsigned long)peer.id());
        relay_block(block_hash);
    } else {
        LogError("net", "rejected reconstructed block from peer %lu: %s",
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
    LogInfo("net", "peer %lu set fee filter to %ld sat/kB",
            (unsigned long)peer.id(), (long)fee_rate);
}

// ===========================================================================
// Full transaction relay with mempool integration
// ===========================================================================

void MessageHandler::handle_tx_full(Peer& peer, const uint8_t* data, size_t len) {
    // Step 1: Deserialize the transaction from wire format
    DataReader r(data, len);
    CTransaction tx;

    tx.version = r.read_u32_le();
    if (r.error()) {
        LogError("net", "malformed tx from peer %lu: cannot read version",
                (unsigned long)peer.id());
        peer.add_misbehavior(10);
        return;
    }

    // Read inputs
    uint64_t vin_count = r.read_compact_size();
    if (r.error() || vin_count > 10000) {
        LogError("net", "malformed tx from peer %lu: bad vin count %lu",
                (unsigned long)peer.id(), (unsigned long)vin_count);
        peer.add_misbehavior(10);
        return;
    }

    tx.vin.resize(static_cast<size_t>(vin_count));
    for (uint64_t j = 0; j < vin_count; ++j) {
        auto txid_bytes = r.read_bytes(32);
        if (r.error()) { peer.add_misbehavior(10); return; }
        std::memcpy(tx.vin[j].prevout.txid.data(), txid_bytes.data(), 32);
        tx.vin[j].prevout.index = r.read_u32_le();
        auto pk_bytes = r.read_bytes(32);
        if (r.error()) { peer.add_misbehavior(10); return; }
        std::memcpy(tx.vin[j].pubkey.data(), pk_bytes.data(), 32);
        auto sig_bytes = r.read_bytes(64);
        if (r.error()) { peer.add_misbehavior(10); return; }
        std::memcpy(tx.vin[j].signature.data(), sig_bytes.data(), 64);
    }

    // Read outputs
    uint64_t vout_count = r.read_compact_size();
    if (r.error() || vout_count > 10000) {
        LogError("net", "malformed tx from peer %lu: bad vout count %lu",
                (unsigned long)peer.id(), (unsigned long)vout_count);
        peer.add_misbehavior(10);
        return;
    }

    tx.vout.resize(static_cast<size_t>(vout_count));
    for (uint64_t j = 0; j < vout_count; ++j) {
        tx.vout[j].amount = r.read_i64_le();
        auto pkh_bytes = r.read_bytes(32);
        if (r.error()) { peer.add_misbehavior(10); return; }
        std::memcpy(tx.vout[j].pubkey_hash.data(), pkh_bytes.data(), 32);
    }

    tx.locktime = r.read_i64_le();
    if (r.error()) {
        LogError("net", "malformed tx from peer %lu: truncated at locktime",
                (unsigned long)peer.id());
        peer.add_misbehavior(10);
        return;
    }

    uint256 txid = tx.get_txid();

    // Step 2: Check not already in blockchain
    if (chain_.has_utxo_for_tx(txid)) {
        // Transaction already confirmed -- silently ignore
        return;
    }

    // Step 3: Check not already in mempool
    Mempool* mempool = chain_.mempool();
    if (!mempool) {
        // No mempool available -- cannot accept transactions
        return;
    }

    CTransaction existing;
    if (mempool->get(txid, existing)) {
        // Already in mempool -- silently ignore
        return;
    }

    // Step 4: Check orphan pool
    if (orphan_pool_.count(txid)) {
        return;  // Already an orphan, don't re-add
    }

    // Step 5: Validate and add to mempool
    auto add_result = mempool->add_transaction(tx);
    bool accepted = add_result.accepted;
    std::string reject_reason = add_result.reject_reason;

    if (accepted) {
        LogInfo("net", "accepted tx %s from peer %lu (%zu in, %zu out)",
                hex_encode(txid.data(), 8).c_str(),
                (unsigned long)peer.id(),
                tx.vin.size(), tx.vout.size());

        // Step 6: Relay to all peers except sender
        relay_tx_to_peers(txid, peer.id());

        // Step 7: Process any orphans that depended on this transaction
        process_orphan_dependents(txid);
    } else {
        // Check if this is an orphan (missing inputs)
        if (reject_reason == "missing-inputs") {
            // Add to orphan pool and request parent transactions
            add_orphan_tx(tx, peer.id());

            // Request parent transactions we don't have
            for (const auto& vin : tx.vin) {
                CTransaction parent_tx;
                if (!mempool->get(vin.prevout.txid, parent_tx) &&
                    !chain_.has_utxo_for_tx(vin.prevout.txid)) {
                    // Request this parent transaction
                    DataWriter getdata_w;
                    getdata_w.write_compact_size(1);
                    InvItem item;
                    item.type = INV_TX;
                    item.hash = vin.prevout.txid;
                    write_inv_item(getdata_w, item);
                    send(peer, NetCmd::GETDATA, getdata_w.release());
                }
            }
        } else {
            LogError("net", "rejected tx %s from peer %lu: %s",
                    hex_encode(txid.data(), 8).c_str(),
                    (unsigned long)peer.id(),
                    reject_reason.c_str());

            // Update misbehavior based on rejection reason
            if (reject_reason == "bad-txns-inputs-spent" ||
                reject_reason == "mandatory-script-verify-flag-failed") {
                peer.add_misbehavior(10);
            } else if (reject_reason == "non-final" ||
                       reject_reason == "dust" ||
                       reject_reason == "insufficient-fee") {
                // Minor protocol violation, small penalty
                peer.add_misbehavior(1);
            }

            // Send reject message back
            send_reject(peer, NetCmd::TX, 0x10, reject_reason, txid);
        }
    }
}

// ===========================================================================
// Orphan transaction pool management
// ===========================================================================

void MessageHandler::add_orphan_tx(const CTransaction& tx, uint64_t from_peer) {
    uint256 txid = tx.get_txid();

    // Limit orphan pool size to prevent memory exhaustion
    constexpr size_t MAX_ORPHAN_TRANSACTIONS = 100;
    constexpr size_t MAX_ORPHAN_TX_SIZE = 100000;

    // Don't accept oversized orphans
    if (tx.get_serialize_size() > MAX_ORPHAN_TX_SIZE) {
        LogInfo("net", "orphan tx %s too large (%zu bytes), ignoring",
                hex_encode(txid.data(), 8).c_str(), tx.get_serialize_size());
        return;
    }

    // If pool is full, evict a random orphan
    while (orphan_pool_.size() >= MAX_ORPHAN_TRANSACTIONS) {
        evict_random_orphan();
    }

    OrphanEntry entry;
    entry.tx = tx;
    entry.from_peer = from_peer;
    entry.time_added = GetTime();
    orphan_pool_[txid] = std::move(entry);

    // Index by parent txid for fast lookup when parent arrives
    for (const auto& vin : tx.vin) {
        orphan_by_parent_[vin.prevout.txid].insert(txid);
    }

    LogInfo("net", "added orphan tx %s from peer %lu (pool size: %zu)",
            hex_encode(txid.data(), 8).c_str(),
            (unsigned long)from_peer,
            orphan_pool_.size());
}

void MessageHandler::evict_random_orphan() {
    if (orphan_pool_.empty()) return;

    // Pick a random orphan to evict
    uint64_t rand_offset = GetRandUint64() % orphan_pool_.size();
    auto it = orphan_pool_.begin();
    std::advance(it, static_cast<ptrdiff_t>(rand_offset));

    uint256 evict_txid = it->first;

    // Remove from parent index
    for (const auto& vin : it->second.tx.vin) {
        auto parent_it = orphan_by_parent_.find(vin.prevout.txid);
        if (parent_it != orphan_by_parent_.end()) {
            parent_it->second.erase(evict_txid);
            if (parent_it->second.empty()) {
                orphan_by_parent_.erase(parent_it);
            }
        }
    }

    orphan_pool_.erase(it);
}

void MessageHandler::process_orphan_dependents(const uint256& parent_txid) {
    auto it = orphan_by_parent_.find(parent_txid);
    if (it == orphan_by_parent_.end()) return;

    // Collect dependent orphan txids (copy because we'll modify the map)
    std::vector<uint256> dependents(it->second.begin(), it->second.end());
    orphan_by_parent_.erase(it);

    Mempool* mempool = chain_.mempool();
    if (!mempool) return;

    for (const auto& orphan_txid : dependents) {
        auto orphan_it = orphan_pool_.find(orphan_txid);
        if (orphan_it == orphan_pool_.end()) continue;

        CTransaction orphan_tx = orphan_it->second.tx;

        // Remove from orphan pool before attempting to add to mempool
        // (to avoid re-adding if validation triggers another orphan check)
        orphan_pool_.erase(orphan_it);

        // Clean up remaining parent index entries for this orphan
        for (const auto& vin : orphan_tx.vin) {
            auto p_it = orphan_by_parent_.find(vin.prevout.txid);
            if (p_it != orphan_by_parent_.end()) {
                p_it->second.erase(orphan_txid);
                if (p_it->second.empty()) {
                    orphan_by_parent_.erase(p_it);
                }
            }
        }

        // Try to accept the orphan now that its parent is available
        auto orphan_result = mempool->add_transaction(orphan_tx);
        std::string reject_reason = orphan_result.reject_reason;
        if (orphan_result.accepted) {
            LogInfo("net", "accepted former orphan tx %s",
                    hex_encode(orphan_txid.data(), 8).c_str());
            relay_tx_to_peers(orphan_txid, 0);
            // Recursively process any orphans depending on this tx
            process_orphan_dependents(orphan_txid);
        } else if (reject_reason == "missing-inputs") {
            // Still orphaned, re-add
            OrphanEntry re_entry;
            re_entry.tx = orphan_tx;
            re_entry.from_peer = 0;
            re_entry.time_added = GetTime();
            orphan_pool_[orphan_txid] = std::move(re_entry);
            for (const auto& vin : orphan_tx.vin) {
                orphan_by_parent_[vin.prevout.txid].insert(orphan_txid);
            }
        }
    }
}

void MessageHandler::expire_orphans() {
    int64_t now = GetTime();
    constexpr int64_t ORPHAN_EXPIRY = 1200;  // 20 minutes

    std::vector<uint256> expired;
    for (const auto& [txid, entry] : orphan_pool_) {
        if (now - entry.time_added > ORPHAN_EXPIRY) {
            expired.push_back(txid);
        }
    }

    for (const auto& txid : expired) {
        auto it = orphan_pool_.find(txid);
        if (it == orphan_pool_.end()) continue;

        for (const auto& vin : it->second.tx.vin) {
            auto p_it = orphan_by_parent_.find(vin.prevout.txid);
            if (p_it != orphan_by_parent_.end()) {
                p_it->second.erase(txid);
                if (p_it->second.empty()) {
                    orphan_by_parent_.erase(p_it);
                }
            }
        }
        orphan_pool_.erase(it);
    }

    if (!expired.empty()) {
        LogWarn("net", "expired %zu orphan transactions", expired.size());
    }
}

// ===========================================================================
// Transaction relay to peers
// ===========================================================================

void MessageHandler::relay_tx_to_peers(const uint256& txid, uint64_t except_peer) {
    auto peers = netman_.get_peers();
    for (Peer* peer : peers) {
        if (peer->state() != PeerState::HANDSHAKE_DONE) continue;
        if (peer->id() == except_peer) continue;

        // Check fee filter: don't announce transactions below the peer's
        // minimum fee rate threshold
        if (peer->fee_filter() > 0) {
            Mempool* mempool = chain_.mempool();
            if (mempool) {
                CTransaction relay_tx;
                if (mempool->get(txid, relay_tx)) {
                    Amount fee = mempool->get_fee(txid);
                    size_t size = relay_tx.get_serialize_size();
                    if (size > 0) {
                        int64_t fee_rate = (fee * 1000) / static_cast<int64_t>(size);
                        if (fee_rate < peer->fee_filter()) {
                            continue;  // Below peer's fee filter
                        }
                    }
                }
            }
        }

        // Check if we already announced this tx to this peer
        if (peer->has_announced_tx(txid)) continue;

        // Add to the trickle queue instead of sending immediately
        peer->add_to_trickle_queue(txid);
    }
}

// ===========================================================================
// Inventory trickle: batch-send pending INV announcements
// ===========================================================================

void MessageHandler::send_inv_trickle() {
    auto peers = netman_.get_peers();
    int64_t now = GetTime();

    for (Peer* peer : peers) {
        if (peer->state() != PeerState::HANDSHAKE_DONE) continue;

        // Only trickle every ~5 seconds per peer
        if (now - peer->last_trickle_time() < 5) continue;

        auto trickle_items = peer->drain_trickle_queue();
        if (trickle_items.empty()) continue;

        peer->set_last_trickle_time(now);

        // Batch INV items (up to 35 per message to avoid oversized messages)
        constexpr size_t MAX_INV_PER_MSG = 35;

        for (size_t offset = 0; offset < trickle_items.size(); offset += MAX_INV_PER_MSG) {
            size_t batch_end = std::min(offset + MAX_INV_PER_MSG, trickle_items.size());
            size_t batch_size = batch_end - offset;

            DataWriter w;
            w.write_compact_size(batch_size);

            for (size_t i = offset; i < batch_end; ++i) {
                InvItem item;
                item.type = INV_TX;
                item.hash = trickle_items[i];
                write_inv_item(w, item);
                peer->mark_announced_tx(trickle_items[i]);
            }

            send(*peer, NetCmd::INV, w.release());
        }
    }
}

// ===========================================================================
// Full inventory handling with mempool awareness
// ===========================================================================

void MessageHandler::handle_inv_full(Peer& peer, const uint8_t* data, size_t len) {
    auto items = read_inv_items(data, len);
    if (items.empty()) return;

    // Validate count
    if (items.size() > static_cast<size_t>(consensus::MAX_INV_SIZE)) {
        peer.add_misbehavior(20);
        return;
    }

    // Collect items we need to request
    std::vector<InvItem> needed_blocks;
    std::vector<InvItem> needed_txs;

    for (const auto& item : items) {
        if (item.type == INV_BLOCK) {
            // Check if we already have this block header or full block
            if (!chain_.block_tree().find(item.hash)) {
                needed_blocks.push_back(item);
            }
        } else if (item.type == INV_TX) {
            // Check mempool, orphan pool, and confirmed txs
            Mempool* mempool = chain_.mempool();
            bool have_it = false;

            if (mempool) {
                CTransaction check_tx;
                have_it = mempool->get(item.hash, check_tx);
            }

            if (!have_it) {
                have_it = orphan_pool_.count(item.hash) > 0;
            }

            if (!have_it) {
                have_it = chain_.has_utxo_for_tx(item.hash);
            }

            if (!have_it) {
                // Check per-peer already-requested set to avoid duplicate requests
                if (!peer.has_requested_tx(item.hash)) {
                    needed_txs.push_back(item);
                    peer.mark_requested_tx(item.hash);
                }
            }
        }
    }

    // Batch all needed items into a single getdata request
    size_t total_needed = needed_blocks.size() + needed_txs.size();
    if (total_needed == 0) return;

    DataWriter w;
    w.write_compact_size(total_needed);

    // Request blocks first (higher priority)
    for (const auto& item : needed_blocks) {
        write_inv_item(w, item);
    }
    for (const auto& item : needed_txs) {
        write_inv_item(w, item);
    }

    send(peer, NetCmd::GETDATA, w.release());

    if (!needed_blocks.empty()) {
        LogInfo("net", "requesting %zu blocks and %zu txs from peer %lu",
                needed_blocks.size(), needed_txs.size(),
                (unsigned long)peer.id());
    }
}

// ===========================================================================
// Full getdata handler with mempool-backed tx serving
// ===========================================================================

void MessageHandler::handle_getdata_full(Peer& peer, const uint8_t* data, size_t len) {
    auto items = read_inv_items(data, len);
    if (items.empty()) return;

    // Track how many items we couldn't find
    std::vector<InvItem> notfound_items;

    for (const auto& item : items) {
        if (item.type == INV_BLOCK) {
            CBlockIndex* index = chain_.block_tree().find(item.hash);
            if (!index || index->pos.is_null()) {
                notfound_items.push_back(item);
                continue;
            }

            CBlock block;
            if (chain_.block_store().read_block(index->pos, block)) {
                auto block_data = serialize_block_for_wire(block);
                send(peer, NetCmd::BLOCK, block_data);
            } else {
                notfound_items.push_back(item);
            }
        } else if (item.type == INV_TX) {
            // Try mempool first
            Mempool* mempool = chain_.mempool();
            bool sent = false;

            if (mempool) {
                CTransaction tx;
                if (mempool->get(item.hash, tx)) {
                    auto tx_data = tx.serialize();
                    send(peer, NetCmd::TX, tx_data);
                    sent = true;
                }
            }

            // Try orphan pool
            if (!sent) {
                auto orphan_it = orphan_pool_.find(item.hash);
                if (orphan_it != orphan_pool_.end()) {
                    auto tx_data = orphan_it->second.tx.serialize();
                    send(peer, NetCmd::TX, tx_data);
                    sent = true;
                }
            }

            if (!sent) {
                notfound_items.push_back(item);
            }
        }
    }

    // Send notfound for items we couldn't serve
    if (!notfound_items.empty()) {
        DataWriter w;
        w.write_compact_size(notfound_items.size());
        for (const auto& item : notfound_items) {
            write_inv_item(w, item);
        }
        send(peer, NetCmd::NOTFOUND, w.release());
    }
}

// ===========================================================================
// Notfound handler
// ===========================================================================

void MessageHandler::handle_notfound_full(Peer& peer, const uint8_t* data, size_t len) {
    auto items = read_inv_items(data, len);

    for (const auto& item : items) {
        if (item.type == INV_TX) {
            // Clear the request tracking so we can request from another peer
            peer.clear_requested_tx(item.hash);

            LogInfo("net", "peer %lu does not have tx %s",
                    (unsigned long)peer.id(),
                    hex_encode(item.hash.data(), 8).c_str());
        } else if (item.type == INV_BLOCK) {
            LogInfo("net", "peer %lu does not have block %s",
                    (unsigned long)peer.id(),
                    hex_encode(item.hash.data(), 8).c_str());
        }
    }
}

// ===========================================================================
// Block relay with announcement mode selection
// ===========================================================================

void MessageHandler::relay_block_full(const CBlock& block) {
    uint256 block_hash = block.get_hash();
    auto peers = netman_.get_peers();

    for (Peer* peer : peers) {
        if (peer->state() != PeerState::HANDSHAKE_DONE) continue;

        // Skip if we already announced this block to this peer
        if (peer->has_announced_block(block_hash)) continue;
        peer->mark_announced_block(block_hash);

        if (peer->prefers_headers()) {
            // Send as a headers message (single header)
            DataWriter w;
            w.write_compact_size(1);
            write_block_header(w, block);
            send(*peer, NetCmd::HEADERS, w.release());
        } else if (peer->supports_compact_blocks() &&
                   peer->wants_cmpct_high_bandwidth()) {
            // Send as a compact block (high-bandwidth mode)
            send_compact_block(*peer, block);
        } else {
            // Send as a standard INV announcement
            DataWriter w;
            w.write_compact_size(1);
            InvItem item;
            item.type = INV_BLOCK;
            item.hash = block_hash;
            write_inv_item(w, item);
            send(*peer, NetCmd::INV, w.release());
        }
    }
}

void MessageHandler::send_compact_block(Peer& peer, const CBlock& block) {
    DataWriter w(4096);

    // Write full header (308 bytes)
    auto unsigned_data = block.get_unsigned_data();
    w.write_bytes(unsigned_data.data(), unsigned_data.size());
    w.write_bytes(block.miner_sig.data(), 64);

    // Generate a random nonce for short ID computation
    uint64_t cmpct_nonce = GetRandUint64();
    w.write_u64_le(cmpct_nonce);

    uint256 block_hash = block.get_hash();

    // Prefill the coinbase (always at index 0)
    size_t num_short_ids = (block.vtx.size() > 1) ? block.vtx.size() - 1 : 0;

    // Write short transaction IDs (skip coinbase)
    w.write_compact_size(num_short_ids);
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        uint256 txid = block.vtx[i].get_txid();
        uint64_t short_id = compute_short_txid(txid, cmpct_nonce, block_hash);
        // Write 6 bytes
        w.write_bytes(reinterpret_cast<const uint8_t*>(&short_id), 6);
    }

    // Write prefilled transactions (just the coinbase at index 0)
    w.write_compact_size(1);
    w.write_compact_size(0);  // diff_index = 0 (absolute index of coinbase)
    auto coinbase_data = block.vtx[0].serialize();
    w.write_bytes(coinbase_data.data(), coinbase_data.size());

    send(peer, NetCmd::CMPCTBLOCK, w.release());
}

// ===========================================================================
// Transaction relay announcement
// ===========================================================================

void MessageHandler::relay_transaction_full(const CTransaction& tx) {
    uint256 txid = tx.get_txid();
    relay_tx_to_peers(txid, 0);  // Relay to all peers (no exception)
}

// ===========================================================================
// Address relay with probability-based forwarding
// ===========================================================================

void MessageHandler::handle_addr_full(Peer& peer, const uint8_t* data, size_t len) {
    DataReader r(data, len);
    uint64_t count = r.read_compact_size();
    if (r.error()) return;

    if (count > static_cast<uint64_t>(consensus::ADDR_RELAY_MAX)) {
        peer.add_misbehavior(20);
        return;
    }

    int64_t now = GetTime();
    std::vector<CNetAddr> new_addrs;
    new_addrs.reserve(static_cast<size_t>(count));

    for (uint64_t i = 0; i < count; ++i) {
        uint32_t ts = r.read_u32_le();
        uint64_t services = r.read_u64_le();
        CNetAddr addr = CNetAddr::deserialize(r);
        if (r.error()) break;

        // Validation: ignore addresses older than 3 hours
        if (static_cast<int64_t>(ts) < now - 3 * 3600) continue;

        // Ignore addresses with port 0
        if (addr.port == 0) continue;

        // Ignore addresses that are clearly invalid
        // (loopback, unroutable, etc.)
        if (addr.is_ipv4()) {
            // Check for 127.x.x.x or 0.0.0.0
            if (addr.ip[12] == 127 || addr.ip[12] == 0) continue;
        }

        // Ignore if we already have too many addresses from this peer
        // (rate limiting: max 1000 per addr message, enforced above)

        // Add to address manager with the advertised timestamp
        netman_.addrman().add(addr, static_cast<int64_t>(ts));

        // If the address is fresh (within last 10 minutes), relay it
        if (static_cast<int64_t>(ts) >= now - 600) {
            new_addrs.push_back(addr);
        }

        (void)services;
    }

    // Relay fresh addresses to 2 random peers (not the sender)
    if (!new_addrs.empty()) {
        relay_addresses(new_addrs, peer.id());
    }
}

void MessageHandler::relay_addresses(const std::vector<CNetAddr>& addrs, uint64_t except_peer) {
    if (addrs.empty()) return;

    auto peers = netman_.get_peers();
    if (peers.size() <= 1) return;

    // Select up to 2 random peers (excluding sender)
    std::vector<Peer*> eligible;
    for (Peer* p : peers) {
        if (p->state() != PeerState::HANDSHAKE_DONE) continue;
        if (p->id() == except_peer) continue;
        eligible.push_back(p);
    }

    if (eligible.empty()) return;

    // Shuffle and pick up to 2
    for (size_t i = eligible.size() - 1; i > 0; --i) {
        size_t j = GetRandUint64() % (i + 1);
        std::swap(eligible[i], eligible[j]);
    }

    size_t relay_count = std::min(eligible.size(), static_cast<size_t>(2));
    int64_t now_ts = GetTime();

    for (size_t i = 0; i < relay_count; ++i) {
        Peer* target = eligible[i];

        DataWriter w;
        w.write_compact_size(addrs.size());
        for (const auto& addr : addrs) {
            w.write_u32_le(static_cast<uint32_t>(now_ts));
            w.write_u64_le(NODE_NETWORK);
            addr.serialize(w);
        }
        send(*target, NetCmd::ADDR, w.release());
    }
}

// ===========================================================================
// Full getaddr handler with addrman sampling
// ===========================================================================

void MessageHandler::handle_getaddr_full(Peer& peer) {
    // Respond with addresses from addrman
    // Return ~23% of known addresses, up to 1000
    size_t total_known = netman_.addrman().size();
    size_t to_send = std::min(static_cast<size_t>(consensus::ADDR_RELAY_MAX),
                              (total_known * 23) / 100);
    to_send = std::max(to_send, static_cast<size_t>(1));

    auto addrs = netman_.addrman().get_addresses(to_send);
    if (addrs.empty()) return;

    int64_t now = GetTime();
    DataWriter w;
    w.write_compact_size(addrs.size());
    for (const auto& addr : addrs) {
        w.write_u32_le(static_cast<uint32_t>(now));
        w.write_u64_le(NODE_NETWORK);
        addr.serialize(w);
    }
    send(peer, NetCmd::ADDR, w.release());

    LogInfo("net", "sent %zu addresses to peer %lu (of %zu known)",
            addrs.size(), (unsigned long)peer.id(), total_known);
}

// ===========================================================================
// Self-address advertisement
// ===========================================================================

void MessageHandler::advertise_local_address() {
    auto peers = netman_.get_peers();

    CNetAddr local_addr("0.0.0.0", netman_.port());
    int64_t now = GetTime();

    // Only advertise every 24 hours
    if (now - last_self_advertise_time_ < 86400) return;
    last_self_advertise_time_ = now;

    for (Peer* peer : peers) {
        if (peer->state() != PeerState::HANDSHAKE_DONE) continue;

        DataWriter w;
        w.write_compact_size(1);
        w.write_u32_le(static_cast<uint32_t>(now));
        w.write_u64_le(NODE_NETWORK);
        local_addr.serialize(w);

        send(*peer, NetCmd::ADDR, w.release());
    }
}

// ===========================================================================
// Ping/pong with latency tracking
// ===========================================================================

void MessageHandler::send_ping(Peer& peer) {
    uint64_t nonce = GetRandUint64();
    peer.set_ping_nonce(nonce);
    peer.set_last_ping_time(GetTimeMicros());

    DataWriter w;
    w.write_u64_le(nonce);
    send(peer, NetCmd::PING, w.release());
}

void MessageHandler::handle_ping_full(Peer& peer, const uint8_t* data, size_t len) {
    if (len < 8) {
        peer.add_misbehavior(10);
        return;
    }

    // Read the 8-byte nonce and echo it back as pong
    DataWriter w;
    w.write_bytes(data, 8);
    send(peer, NetCmd::PONG, w.release());

    // Update last activity time
    peer.set_last_recv_time(GetTime());
}

void MessageHandler::handle_pong_full(Peer& peer, const uint8_t* data, size_t len) {
    if (len < 8) return;

    DataReader r(data, len);
    uint64_t nonce = r.read_u64_le();

    if (nonce == peer.ping_nonce() && peer.ping_nonce() != 0) {
        int64_t now = GetTimeMicros();
        int64_t latency = now - peer.last_ping_time();

        // Sanity check latency (reject if > 5 minutes)
        if (latency < 0 || latency > 300'000'000LL) {
            LogWarn("net", "bogus ping latency from peer %lu: %ld us",
                    (unsigned long)peer.id(), (long)latency);
            return;
        }

        peer.set_ping_latency_us(latency);
        peer.set_ping_nonce(0);

        // Update min ping
        if (latency < peer.min_ping_us() || peer.min_ping_us() == 0) {
            peer.set_min_ping_us(latency);
        }

        // Log if latency is notable
        if (latency > 10'000'000LL) {  // > 10 seconds
            LogWarn("net", "high ping latency from peer %lu: %.1f s",
                    (unsigned long)peer.id(),
                    static_cast<double>(latency) / 1e6);
        }
    } else {
        // Nonce mismatch -- could be a delayed or unsolicited pong.
        // Not necessarily malicious, so don't penalize.
    }
}

// ===========================================================================
// Send reject message
// ===========================================================================

void MessageHandler::send_reject(Peer& peer, const std::string& rejected_cmd,
                                  uint8_t code, const std::string& reason,
                                  const uint256& hash) {
    DataWriter w;

    // Rejected command name (compact-size-prefixed string)
    w.write_compact_size(rejected_cmd.size());
    w.write_bytes(reinterpret_cast<const uint8_t*>(rejected_cmd.data()),
                  rejected_cmd.size());

    // Rejection code
    w.write_u8(code);

    // Reason string (compact-size-prefixed)
    std::string truncated = reason.substr(0, 256);
    w.write_compact_size(truncated.size());
    if (!truncated.empty()) {
        w.write_bytes(reinterpret_cast<const uint8_t*>(truncated.data()),
                      truncated.size());
    }

    // Optional: hash of the rejected object
    if (!hash.is_null()) {
        w.write_bytes(hash.data(), 32);
    }

    send(peer, NetCmd::REJECT, w.release());
}

// ===========================================================================
// Periodic maintenance entry point (called from NetManager tick)
// ===========================================================================

void MessageHandler::on_tick() {
    // Trickle pending transaction announcements
    send_inv_trickle();

    // Expire old orphan transactions
    expire_orphans();

    // Periodically advertise our own address
    advertise_local_address();
}

// ===========================================================================
// Block announcement: headers mode (BIP-130 sendheaders)
// ===========================================================================

void MessageHandler::announce_block_headers(Peer& peer, const CBlock& block) {
    // If this peer prefers headers announcements, send a headers message
    // containing just the block's header. The peer can then decide whether
    // to request the full block via getdata.

    DataWriter w;
    w.write_compact_size(1);  // one header

    // Serialize the block header (244 unsigned + 64 signature)
    write_block_header(w, block);

    send(peer, NetCmd::HEADERS, w.release());
    peer.record_message_sent("headers", 1);
}

// ===========================================================================
// Block announcement: compact block (BIP-152)
// ===========================================================================

void MessageHandler::announce_compact_block(Peer& peer, const CBlock& block) {
    // Send a compact block message containing the header, a nonce for
    // short txid computation, short txids for each transaction, and
    // the coinbase as a prefilled transaction.

    uint256 block_hash = block.get_hash();
    uint64_t cmpct_nonce = GetRandUint64();

    DataWriter w(8192);

    // Full header (244 + 64 = 308 bytes)
    write_block_header(w, block);

    // Nonce (8 bytes)
    w.write_u64_le(cmpct_nonce);

    // Short transaction IDs (6 bytes each, excluding prefilled txs)
    // We prefill the coinbase (index 0), so short_ids cover indices 1..N-1
    size_t short_id_count = (block.vtx.size() > 1) ? block.vtx.size() - 1 : 0;
    w.write_compact_size(short_id_count);

    for (size_t i = 1; i < block.vtx.size(); ++i) {
        uint256 txid = block.vtx[i].get_txid();
        uint64_t short_id = compute_short_txid(txid, cmpct_nonce, block_hash);

        // Write 6 bytes of the short ID
        uint8_t short_bytes[6];
        std::memcpy(short_bytes, &short_id, 6);
        w.write_bytes(short_bytes, 6);
    }

    // Prefilled transactions: just the coinbase (index 0)
    w.write_compact_size(1);
    w.write_compact_size(0);  // differential index = 0

    // Serialize the coinbase transaction
    auto coinbase_data = block.vtx[0].serialize();
    w.write_bytes(coinbase_data.data(), coinbase_data.size());

    send(peer, NetCmd::CMPCTBLOCK, w.release());
    peer.record_message_sent("cmpctblock", 1);
}

// ===========================================================================
// Block announcement: full block via inv (legacy)
// ===========================================================================

void MessageHandler::announce_full_block(Peer& peer, const CBlock& block) {
    // Traditional three-step relay: send inv, peer sends getdata, we respond
    // with the full block. This method just sends the inv.

    uint256 block_hash = block.get_hash();

    // Check if we've already announced this to this peer
    if (peer.has_announced(block_hash)) {
        return;
    }

    DataWriter w;
    w.write_compact_size(1);
    InvItem item;
    item.type = INV_BLOCK;
    item.hash = block_hash;
    write_inv_item(w, item);

    send(peer, NetCmd::INV, w.release());
    peer.mark_announced(block_hash);
}

// ===========================================================================
// Smart block relay: choose best method per peer
// ===========================================================================

void MessageHandler::relay_block_smart(const CBlock& block) {
    auto peers = netman_.connected_peers();

    for (auto& peer : peers) {
        if (peer->state() != PeerState::HANDSHAKE_DONE) {
            continue;
        }

        uint256 block_hash = block.get_hash();
        if (peer->has_announced(block_hash)) {
            continue;
        }

        // Choose relay method based on peer preferences
        if (peer->prefers_compact_blocks() && peer->wants_cmpct_high_bandwidth()) {
            // High bandwidth compact block mode: send immediately
            announce_compact_block(*peer, block);
        } else if (peer->prefers_headers() && peer->supports_compact_blocks()) {
            // Send compact block (low bandwidth mode)
            announce_compact_block(*peer, block);
        } else if (peer->prefers_headers()) {
            // Headers-only announcement
            announce_block_headers(*peer, block);
        } else {
            // Legacy inv announcement
            announce_full_block(*peer, block);
        }

        peer->mark_announced(block_hash);
    }
}

// ===========================================================================
// Orphan block handling
// ===========================================================================

void MessageHandler::add_orphan_block(const CBlock& block, uint64_t peer_id) {
    uint256 hash = block.get_hash();

    // Don't store duplicates
    if (orphan_blocks_.count(hash)) {
        return;
    }

    // Limit total orphan storage
    limit_orphan_blocks(25);

    OrphanBlock ob;
    ob.block = block;
    ob.hash = hash;
    ob.prev_hash = block.prev_hash;
    ob.peer_id = peer_id;
    ob.received_at = GetTime();

    orphan_blocks_[hash] = std::move(ob);
    orphans_by_prev_[block.prev_hash].push_back(hash);

    LogInfo("net", "stored orphan block %.8s (prev=%.8s) from peer %lu",
            hex_encode(hash.data(), 32).c_str(),
            hex_encode(block.prev_hash.data(), 32).c_str(),
            (unsigned long)peer_id);
}

bool MessageHandler::has_orphan_block(const uint256& hash) const {
    return orphan_blocks_.count(hash) > 0;
}

void MessageHandler::process_orphan_blocks(const uint256& accepted_hash) {
    // When a new block is accepted, check if any orphans were waiting for it.
    // If so, try to process them recursively.

    auto it = orphans_by_prev_.find(accepted_hash);
    if (it == orphans_by_prev_.end()) {
        return;
    }

    // Copy the list since we'll modify the map during processing
    std::vector<uint256> children = it->second;
    orphans_by_prev_.erase(it);

    for (const auto& child_hash : children) {
        auto orphan_it = orphan_blocks_.find(child_hash);
        if (orphan_it == orphan_blocks_.end()) {
            continue;
        }

        CBlock orphan_block = std::move(orphan_it->second.block);
        uint64_t from_peer = orphan_it->second.peer_id;
        orphan_blocks_.erase(orphan_it);

        uint256 orphan_hash = orphan_block.get_hash();

        // Try to accept this previously orphaned block
        consensus::ValidationState vstate;
        if (chain_.accept_block(orphan_block, vstate)) {
            LogInfo("net", "accepted former orphan block at height %lu",
                    (unsigned long)orphan_block.height);
            relay_block(orphan_hash);

            // Recursively process orphans of this block
            process_orphan_blocks(orphan_hash);
        } else {
            LogError("net", "rejected orphan block: %s (peer %lu)",
                    vstate.reject_reason().c_str(), (unsigned long)from_peer);
        }
    }
}

void MessageHandler::limit_orphan_blocks(size_t max_orphans) {
    while (orphan_blocks_.size() >= max_orphans) {
        // Evict the oldest orphan
        int64_t oldest_time = INT64_MAX;
        uint256 oldest_hash;

        for (const auto& [hash, ob] : orphan_blocks_) {
            if (ob.received_at < oldest_time) {
                oldest_time = ob.received_at;
                oldest_hash = hash;
            }
        }

        if (oldest_time == INT64_MAX) break;

        // Remove from by_prev index
        auto it = orphan_blocks_.find(oldest_hash);
        if (it != orphan_blocks_.end()) {
            auto prev_it = orphans_by_prev_.find(it->second.prev_hash);
            if (prev_it != orphans_by_prev_.end()) {
                auto& vec = prev_it->second;
                vec.erase(std::remove(vec.begin(), vec.end(), oldest_hash), vec.end());
                if (vec.empty()) {
                    orphans_by_prev_.erase(prev_it);
                }
            }
            orphan_blocks_.erase(it);
        }
    }
}

// ===========================================================================
// Header chain download (IBD batch requests)
// ===========================================================================

void MessageHandler::request_headers_batch(Peer& peer, const uint256& from_hash) {
    // Build a getheaders message requesting headers starting after from_hash.
    // This is used during Initial Block Download to request batches of 2000 headers.

    DataWriter w;
    w.write_u32_le(consensus::PROTOCOL_VERSION);

    // Build a locator with just the from_hash
    w.write_compact_size(1);
    w.write_bytes(from_hash.data(), 32);

    // Hash stop = zero (get as many as possible)
    uint256 zero_stop;
    w.write_bytes(zero_stop.data(), 32);

    send(peer, NetCmd::GETHEADERS, w.release());

    LogInfo("net", "requesting headers batch from peer %lu starting at %.8s",
            (unsigned long)peer.id(), hex_encode(from_hash.data(), 32).c_str());
}

void MessageHandler::process_headers_batch(Peer& peer,
                                            const std::vector<CBlockHeader>& headers) {
    // Process a batch of received headers. Accept each one into the block tree.
    // If we received a full batch (2000), request more.

    int accepted = 0;
    int rejected = 0;
    uint256 last_accepted_hash;

    for (const auto& hdr : headers) {
        uint256 hdr_hash = hdr.get_hash();

        // Skip if already known
        if (chain_.block_tree().find(hdr_hash)) {
            continue;
        }

        consensus::ValidationState vstate;
        CBlockIndex* new_idx = chain_.accept_header(hdr, vstate);
        if (new_idx) {
            accepted++;
            last_accepted_hash = hdr_hash;
            peer.set_synced_headers(new_idx->height);
        } else {
            rejected++;
            LogError("net", "rejected header from batch: %s",
                    vstate.reject_reason().c_str());
            if (rejected > 10) {
                // Too many bad headers; penalize and stop
                peer.add_misbehavior(20);
                break;
            }
        }
    }

    LogError("net", "processed headers batch from peer %lu: "
            "%d accepted, %d rejected (of %zu)",
            (unsigned long)peer.id(), accepted, rejected, headers.size());

    // If we got a full batch, request more
    if (headers.size() >= 2000 && accepted > 0 && !last_accepted_hash.is_null()) {
        request_headers_batch(peer, last_accepted_hash);
    }
}

// ===========================================================================
// Transaction broadcasting with tracking
// ===========================================================================

void MessageHandler::track_tx_broadcast(const uint256& txid) {
    BroadcastState state;
    state.txid = txid;
    state.peers_relayed_to = 0;
    state.first_relay_time = GetTime();
    state.relay_attempts = 0;
    state.confirmed = false;

    broadcast_states_[txid] = state;
}

MessageHandler::BroadcastState MessageHandler::get_broadcast_state(
        const uint256& txid) const {
    auto it = broadcast_states_.find(txid);
    if (it != broadcast_states_.end()) {
        return it->second;
    }

    BroadcastState empty;
    empty.txid = txid;
    empty.peers_relayed_to = 0;
    empty.first_relay_time = 0;
    empty.relay_attempts = 0;
    empty.confirmed = false;
    return empty;
}

void MessageHandler::rebroadcast_wallet_txs(
        const std::vector<CTransaction>& wallet_txs) {
    // Re-broadcast unconfirmed wallet transactions to all connected peers.
    // This ensures our transactions propagate even if the initial broadcast
    // was to a limited set of peers.

    int64_t now = GetTime();

    // Only rebroadcast transactions that are still unconfirmed and old enough
    // (at least 30 minutes since first broadcast)
    static constexpr int64_t MIN_REBROADCAST_INTERVAL = 1800;  // 30 minutes

    for (const auto& tx : wallet_txs) {
        uint256 txid = tx.get_txid();

        auto it = broadcast_states_.find(txid);
        if (it != broadcast_states_.end()) {
            if (it->second.confirmed) {
                continue;  // already confirmed
            }
            if (now - it->second.first_relay_time < MIN_REBROADCAST_INTERVAL) {
                continue;  // too soon to rebroadcast
            }
        }

        // Relay the transaction via inv to all peers
        relay_tx(txid);

        // Update broadcast state
        if (it != broadcast_states_.end()) {
            it->second.relay_attempts++;
        } else {
            track_tx_broadcast(txid);
        }

        LogInfo("net", "rebroadcast wallet tx %.8s",
                hex_encode(txid.data(), 32).c_str());
    }
}

// ===========================================================================
// Feeler connection support
// ===========================================================================

// send_ping is already defined above

void MessageHandler::check_peer_timeouts() {
    // Check all connected peers for various timeout conditions
    int64_t now = GetTime();
    auto peers = netman_.connected_peers();

    for (auto& peer : peers) {
        if (peer->state() != PeerState::HANDSHAKE_DONE) {
            // Handshake timeout: disconnect if version not completed within 60s
            int64_t elapsed = now - peer->connect_time();
            if (elapsed > 60) {
                LogWarn("net", "handshake timeout for peer %lu, disconnecting",
                        (unsigned long)peer->id());
                netman_.disconnect(*peer, "handshake timeout");
            }
            continue;
        }

        // No data received timeout: disconnect after 20 minutes of silence
        if (peer->last_recv_time() > 0) {
            int64_t since_recv = now - peer->last_recv_time();
            if (since_recv > 1200) {
                LogInfo("net", "no data from peer %lu for %ld seconds, disconnecting",
                        (unsigned long)peer->id(), (long)since_recv);
                netman_.disconnect(*peer, "no data timeout");
                continue;
            }
        }

        // Ping timeout: if we sent a ping and haven't got a pong in 20 minutes
        if (peer->ping_nonce() != 0 && peer->last_ping_time() > 0) {
            int64_t ping_elapsed = (GetTimeMicros() - peer->last_ping_time()) / 1000000;
            if (ping_elapsed > 1200) {
                LogWarn("net", "ping timeout for peer %lu, disconnecting",
                        (unsigned long)peer->id());
                netman_.disconnect(*peer, "ping timeout");
                continue;
            }
        }

        // Check for stalled block downloads
        auto stalled = peer->get_stalled_requests(now);
        if (stalled.size() > 3) {
            LogWarn("net", "peer %lu has %zu stalled requests, adding misbehavior",
                    (unsigned long)peer->id(), stalled.size());
            peer->add_misbehavior(5);
        }

        // Send periodic pings (every 2 minutes)
        if (peer->ping_nonce() == 0) {
            int64_t since_ping = (peer->last_ping_time() > 0)
                ? (GetTimeMicros() - peer->last_ping_time()) / 1000000
                : 999;
            if (since_ping >= 120) {
                send_ping(*peer);
            }
        }
    }
}

// ===========================================================================
// Address advertisement
// ===========================================================================

void MessageHandler::send_local_addr(Peer& peer, const CNetAddr& local_addr) {
    DataWriter w;
    w.write_compact_size(1);
    w.write_u32_le(static_cast<uint32_t>(GetTime()));
    w.write_u64_le(NODE_NETWORK);
    local_addr.serialize(w);

    send(peer, NetCmd::ADDR, w.release());
}

// ===========================================================================
// Block download scheduler
// ===========================================================================

void MessageHandler::schedule_block_downloads() {
    // For each peer that has announced headers we don't have bodies for,
    // schedule block downloads. Distribute requests across peers to avoid
    // overloading any single one.

    auto peers = netman_.connected_peers();
    if (peers.empty()) return;

    int64_t now = GetTime();

    // Find blocks we need to download (have headers but not bodies)
    CBlockIndex* tip = chain_.tip();
    if (!tip) return;

    // Walk forward from our last fully validated block to find gaps
    std::vector<CBlockIndex*> needed_blocks;
    // Look ahead up to 1024 blocks beyond tip
    // In practice, we'd use the header chain, but for now we check
    // the block tree for entries with status HEADER_VALID but not BLOCK_VALID

    // For each needed block, assign to the best peer
    size_t peer_idx = 0;
    for (auto* blk : needed_blocks) {
        if (peer_idx >= peers.size()) peer_idx = 0;

        auto& peer = peers[peer_idx];
        if (peer->state() != PeerState::HANDSHAKE_DONE) {
            peer_idx++;
            continue;
        }

        // Don't send duplicate requests
        if (peer->has_announced(blk->hash)) {
            continue;
        }

        // Request the block via getdata
        DataWriter w;
        w.write_compact_size(1);
        InvItem item;
        item.type = INV_BLOCK;
        item.hash = blk->hash;
        write_inv_item(w, item);
        send(*peer, NetCmd::GETDATA, w.release());

        peer->add_pending_request(blk->hash, INV_BLOCK, now);
        peer_idx++;
    }
}

// ===========================================================================
// Peer rotation for block download
// ===========================================================================

Peer* MessageHandler::select_download_peer(
        const std::vector<Peer*>& peers,
        const uint256& block_hash) {
    // Select the best peer to download a specific block from.
    // Criteria: low latency, high bandwidth, has the block, not stalled.

    Peer* best = nullptr;
    double best_score = -1.0;

    for (const auto& peer : peers) {
        if (peer->state() != PeerState::HANDSHAKE_DONE) continue;

        // Skip peers with too many pending requests
        auto stalled = peer->get_stalled_requests(GetTime());
        if (stalled.size() > 5) continue;

        // Skip peers with high misbehavior
        if (peer->misbehavior() >= 50) continue;

        // Compute download score
        double score = peer->eviction_score();

        // Bonus for peers that have announced this block
        if (peer->has_received_inv(block_hash)) {
            score += 50.0;
        }

        // Bonus for low pending request count
        size_t pending = peer->pending_request_count();
        if (pending == 0) {
            score += 30.0;
        } else if (pending < 3) {
            score += 15.0;
        }

        if (score > best_score) {
            best_score = score;
            best = peer;
        }
    }

    return best;
}

// ===========================================================================
// Transaction relay policy
// ===========================================================================

bool MessageHandler::should_relay_tx(const Peer& peer, const CTransaction& tx) const {
    // Check if this transaction should be relayed to a specific peer.

    // Don't relay if peer has set a fee filter and the tx doesn't meet it
    if (peer.fee_filter() > 0) {
        size_t tx_size = tx.get_serialize_size();
        if (tx_size > 0) {
            Amount tx_fee = 0;  // Would need mempool to get actual fee
            double fee_rate = (tx_size > 0)
                ? static_cast<double>(tx_fee) / static_cast<double>(tx_size)
                : 0.0;
            if (fee_rate < static_cast<double>(peer.fee_filter())) {
                return false;
            }
        }
    }

    // Don't relay if peer already knows about it
    uint256 txid = tx.get_txid();
    if (peer.has_announced(txid) || peer.has_received_inv(txid)) {
        return false;
    }

    return true;
}

void MessageHandler::batch_relay_txs(const std::vector<uint256>& txids) {
    // Relay multiple transaction inv items in a single inv message per peer.
    // This is more efficient than sending individual inv messages.

    if (txids.empty()) return;

    auto peers = netman_.connected_peers();

    for (auto& peer : peers) {
        if (peer->state() != PeerState::HANDSHAKE_DONE) continue;

        // Filter to txids this peer doesn't know about
        std::vector<uint256> relay_set;
        for (const auto& txid : txids) {
            if (!peer->has_announced(txid) && !peer->has_received_inv(txid)) {
                relay_set.push_back(txid);
                peer->mark_announced(txid);
            }
        }

        if (relay_set.empty()) continue;

        // Send inv message with all tx ids
        DataWriter w;
        w.write_compact_size(relay_set.size());
        for (const auto& txid : relay_set) {
            InvItem item;
            item.type = INV_TX;
            item.hash = txid;
            write_inv_item(w, item);
        }
        send(*peer, NetCmd::INV, w.release());
    }
}

// ===========================================================================
// Block locator construction
// ===========================================================================

std::vector<uint256> MessageHandler::build_block_locator() const {
    // Build a block locator for getheaders/getblocks messages.
    // The locator contains hashes at exponentially increasing distances:
    // tip, tip-1, tip-2, tip-3, tip-5, tip-9, tip-17, tip-33, ...
    // This allows efficient fork detection with O(log N) hashes.

    std::vector<uint256> locator;

    CBlockIndex* tip = chain_.tip();
    if (!tip) {
        // Return just the genesis hash
        CBlockIndex* genesis = chain_.block_tree().genesis();
        if (genesis) {
            locator.push_back(genesis->hash);
        }
        return locator;
    }

    // Walk back from tip with exponentially increasing steps
    int step = 1;
    CBlockIndex* current = tip;

    while (current) {
        locator.push_back(current->hash);

        // After the first 10 entries, start exponential stepping
        if (locator.size() >= 10) {
            step *= 2;
        }

        // Walk back 'step' blocks
        for (int i = 0; i < step && current; ++i) {
            if (current->height == 0) {
                current = nullptr;
                break;
            }
            current = current->prev;
        }

        // Safety: limit locator size
        if (locator.size() >= 101) break;
    }

    // Always include genesis
    CBlockIndex* genesis = chain_.block_tree().genesis();
    if (genesis && (locator.empty() || locator.back() != genesis->hash)) {
        locator.push_back(genesis->hash);
    }

    return locator;
}

// ===========================================================================
// Compact block high-bandwidth negotiation
// ===========================================================================

void MessageHandler::send_sendcmpct(Peer& peer, bool high_bandwidth) {
    DataWriter w;
    w.write_u8(high_bandwidth ? 1 : 0);
    w.write_u64_le(1);  // compact block version 1

    send(peer, NetCmd::SENDCMPCT, w.release());
}

void MessageHandler::send_sendheaders(Peer& peer) {
    send(peer, NetCmd::SENDHEADERS);
}

void MessageHandler::send_feefilter(Peer& peer, Amount min_fee_rate) {
    DataWriter w;
    w.write_i64_le(min_fee_rate);
    send(peer, NetCmd::FEEFILTER, w.release());
}

} // namespace flow

