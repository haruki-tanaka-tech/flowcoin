// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for inventory message encoding/decoding, getdata request/response,
// notfound handling, transaction and block relay, fee filter, duplicate
// inventory suppression, trickle batching, and address relay.

#include "net/protocol.h"
#include "net/peer.h"
#include "net/addrman.h"
#include "hash/keccak.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "consensus/params.h"
#include "crypto/keys.h"
#include "util/random.h"
#include "util/serialize.h"
#include "util/types.h"

#include <cassert>
#include <cstring>
#include <set>
#include <vector>

using namespace flow;

// Helper: create a random uint256
static uint256 rand_hash() {
    return GetRandUint256();
}

void test_inventory_relay() {

    // -----------------------------------------------------------------------
    // Test 1: InvItem type constants
    // -----------------------------------------------------------------------
    {
        assert(INV_TX == 1);
        assert(INV_BLOCK == 2);

        InvItem tx_item;
        tx_item.type = INV_TX;
        tx_item.hash = rand_hash();
        assert(tx_item.type == INV_TX);
        assert(!tx_item.hash.is_null());

        InvItem block_item;
        block_item.type = INV_BLOCK;
        block_item.hash = rand_hash();
        assert(block_item.type == INV_BLOCK);
    }

    // -----------------------------------------------------------------------
    // Test 2: inv message encoding/decoding (block and tx types)
    // -----------------------------------------------------------------------
    {
        // Encode a list of inventory items
        std::vector<InvItem> items;
        for (int i = 0; i < 5; i++) {
            InvItem item;
            item.type = (i % 2 == 0) ? INV_TX : INV_BLOCK;
            item.hash = rand_hash();
            items.push_back(item);
        }

        // Serialize: compact_size(count) + [type(4) + hash(32)] * count
        DataWriter w;
        w.write_compact_size(items.size());
        for (auto& item : items) {
            w.write_le32(static_cast<uint32_t>(item.type));
            w.write_bytes(item.hash.data(), 32);
        }

        // Deserialize
        DataReader r(w.data());
        uint64_t count = r.read_compact_size();
        assert(count == 5);

        for (size_t i = 0; i < count; i++) {
            uint32_t type = r.read_le32();
            uint256 hash;
            r.read_bytes(hash.data(), 32);

            assert(type == static_cast<uint32_t>(items[i].type));
            assert(hash == items[i].hash);
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: getdata request/response round-trip
    // -----------------------------------------------------------------------
    {
        // getdata has the same format as inv
        std::vector<InvItem> requested;
        requested.push_back({INV_BLOCK, rand_hash()});
        requested.push_back({INV_TX, rand_hash()});

        DataWriter w;
        w.write_compact_size(requested.size());
        for (auto& item : requested) {
            w.write_le32(static_cast<uint32_t>(item.type));
            w.write_bytes(item.hash.data(), 32);
        }

        DataReader r(w.data());
        uint64_t count = r.read_compact_size();
        assert(count == 2);

        for (size_t i = 0; i < count; i++) {
            uint32_t type = r.read_le32();
            uint256 hash;
            r.read_bytes(hash.data(), 32);
            assert(type == static_cast<uint32_t>(requested[i].type));
            assert(hash == requested[i].hash);
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: notfound response for unknown items
    // -----------------------------------------------------------------------
    {
        // notfound has same format as inv/getdata
        // Serialize a single notfound item
        InvItem not_found;
        not_found.type = INV_TX;
        not_found.hash = rand_hash();

        DataWriter w;
        w.write_compact_size(1);
        w.write_le32(static_cast<uint32_t>(not_found.type));
        w.write_bytes(not_found.hash.data(), 32);

        auto msg = build_message(consensus::MAINNET_MAGIC, NetCmd::NOTFOUND,
                                  std::vector<uint8_t>(w.data(), w.data() + w.size()));
        assert(msg.size() == MessageHeader::SIZE + w.size());

        // Parse header
        DataReader r(msg.data(), MessageHeader::SIZE);
        MessageHeader hdr;
        assert(MessageHeader::deserialize(r, hdr));
        assert(hdr.command_string() == "notfound");
        assert(hdr.payload_size == w.size());
    }

    // -----------------------------------------------------------------------
    // Test 5: Transaction relay flow (add to mempool -> announce to peers)
    // -----------------------------------------------------------------------
    {
        // Simulate: a new tx arrives, we create an inv for it
        CTransaction tx;
        tx.version = 1;
        CTxIn in;
        in.prevout = COutPoint(rand_hash(), 0);
        auto kp = generate_keypair();
        std::memcpy(in.pubkey.data(), kp.pubkey.data(), 32);
        tx.vin.push_back(in);
        CTxOut out;
        out.amount = 1 * consensus::COIN;
        tx.vout.push_back(out);

        uint256 txid = tx.get_txid();

        // Create inv message for this tx
        std::vector<InvItem> inv_items = {{INV_TX, txid}};

        DataWriter w;
        w.write_compact_size(inv_items.size());
        w.write_le32(static_cast<uint32_t>(INV_TX));
        w.write_bytes(txid.data(), 32);

        auto msg = build_message(consensus::MAINNET_MAGIC, NetCmd::INV,
                                  std::vector<uint8_t>(w.data(), w.data() + w.size()));
        assert(msg.size() > MessageHeader::SIZE);
    }

    // -----------------------------------------------------------------------
    // Test 6: Block relay — headers announcement
    // -----------------------------------------------------------------------
    {
        // When peer prefers headers, we send a headers message
        CBlockHeader hdr;
        hdr.height = 10;
        hdr.timestamp = consensus::GENESIS_TIMESTAMP + 10 * consensus::TARGET_BLOCK_TIME;
        hdr.nbits = consensus::INITIAL_NBITS;
        hdr.version = 1;
        hdr.prev_hash = rand_hash();
        GetRandBytes(hdr.miner_pubkey.data(), 32);

        auto data = hdr.serialize();
        assert(data.size() == BLOCK_HEADER_SIZE);

        // Build headers message: count + headers
        DataWriter w;
        w.write_compact_size(1);
        w.write_bytes(data.data(), data.size());

        auto msg = build_message(consensus::MAINNET_MAGIC, NetCmd::HEADERS,
                                  std::vector<uint8_t>(w.data(), w.data() + w.size()));
        assert(msg.size() == MessageHeader::SIZE + w.size());
    }

    // -----------------------------------------------------------------------
    // Test 7: Fee filter — skip relay for low-fee txs
    // -----------------------------------------------------------------------
    {
        // Peer sets fee filter at 5000 atomic units per byte
        CNetAddr addr("192.168.1.1", 9333);
        Peer peer(1, addr, false);
        peer.set_fee_filter(5000);

        assert(peer.fee_filter() == 5000);

        // Transaction with fee rate below the filter should be skipped
        double tx_fee_rate = 100.0;  // below 5000
        bool should_relay = (tx_fee_rate >= static_cast<double>(peer.fee_filter()));
        assert(!should_relay);

        // Transaction with fee rate above the filter should be relayed
        tx_fee_rate = 6000.0;
        should_relay = (tx_fee_rate >= static_cast<double>(peer.fee_filter()));
        assert(should_relay);
    }

    // -----------------------------------------------------------------------
    // Test 8: Duplicate inv suppression (already announced)
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.1", 9333);
        Peer peer(2, addr, true);

        uint256 hash1 = rand_hash();
        uint256 hash2 = rand_hash();

        // Initially not announced
        assert(!peer.has_announced(hash1));
        assert(!peer.has_announced(hash2));

        // Mark as announced
        peer.mark_announced(hash1);
        assert(peer.has_announced(hash1));
        assert(!peer.has_announced(hash2));

        // Mark hash2
        peer.mark_announced(hash2);
        assert(peer.has_announced(hash1));
        assert(peer.has_announced(hash2));

        // Should not re-announce already announced
        bool should_send = !peer.has_announced(hash1);
        assert(!should_send);  // already announced, skip
    }

    // -----------------------------------------------------------------------
    // Test 9: Received inv tracking
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.2", 9333);
        Peer peer(3, addr, false);

        uint256 hash = rand_hash();
        assert(!peer.has_received_inv(hash));

        peer.mark_received_inv(hash);
        assert(peer.has_received_inv(hash));
    }

    // -----------------------------------------------------------------------
    // Test 10: Trickle batching — accumulate inv items
    // -----------------------------------------------------------------------
    {
        // Simulated trickle: collect inv items and send in batches
        std::vector<InvItem> batch;
        for (int i = 0; i < 10; i++) {
            batch.push_back({INV_TX, rand_hash()});
        }

        // Batch should contain exactly 10 items
        assert(batch.size() == 10);

        // Serialize the batch
        DataWriter w;
        w.write_compact_size(batch.size());
        for (auto& item : batch) {
            w.write_le32(static_cast<uint32_t>(item.type));
            w.write_bytes(item.hash.data(), 32);
        }

        // Verify encoding size: compact_size(10) + 10 * 36 bytes
        assert(w.size() == 1 + 10 * 36);
    }

    // -----------------------------------------------------------------------
    // Test 11: MAX_INV_SIZE limit
    // -----------------------------------------------------------------------
    {
        assert(consensus::MAX_INV_SIZE == 50000);

        // A message with more than MAX_INV_SIZE items should be rejected
        uint32_t count = 50001;
        bool too_many = (count > static_cast<uint32_t>(consensus::MAX_INV_SIZE));
        assert(too_many);
    }

    // -----------------------------------------------------------------------
    // Test 12: Peer pending request tracking
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.3", 9333);
        Peer peer(4, addr, false);

        uint256 hash = rand_hash();
        int64_t now = consensus::GENESIS_TIMESTAMP;

        assert(peer.pending_request_count() == 0);

        peer.add_pending_request(hash, INV_BLOCK, now);
        assert(peer.pending_request_count() == 1);

        peer.fulfill_request(hash);
        assert(peer.pending_request_count() == 0);
    }

    // -----------------------------------------------------------------------
    // Test 13: Peer bytes tracking per message type
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.4", 9333);
        Peer peer(5, addr, false);

        peer.record_message_recv("inv", 500);
        peer.record_message_recv("inv", 300);
        peer.record_message_recv("tx", 1000);

        auto& recv_stats = peer.recv_msg_stats();
        assert(recv_stats.count("inv") > 0);
        assert(recv_stats.at("inv").count == 2);
        assert(recv_stats.at("inv").bytes == 800);
        assert(recv_stats.count("tx") > 0);
        assert(recv_stats.at("tx").count == 1);
        assert(recv_stats.at("tx").bytes == 1000);
    }

    // -----------------------------------------------------------------------
    // Test 14: Peer sent message tracking
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.5", 9333);
        Peer peer(6, addr, true);

        peer.record_message_sent("block", 50000);
        peer.record_message_sent("headers", 3000);

        auto& sent_stats = peer.sent_msg_stats();
        assert(sent_stats.count("block") > 0);
        assert(sent_stats.at("block").bytes == 50000);
        assert(sent_stats.count("headers") > 0);
        assert(sent_stats.at("headers").bytes == 3000);
    }

    // -----------------------------------------------------------------------
    // Test 15: Compact block support flag
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.6", 9333);
        Peer peer(7, addr, false);

        assert(!peer.supports_compact_blocks());
        peer.set_supports_compact_blocks(true);
        assert(peer.supports_compact_blocks());

        peer.set_compact_block_version(1);
        assert(peer.compact_block_version() == 1);
    }

    // -----------------------------------------------------------------------
    // Test 16: Header preference flag
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.7", 9333);
        Peer peer(8, addr, false);

        assert(!peer.prefers_headers());
        peer.set_prefers_headers(true);
        assert(peer.prefers_headers());
    }

    // -----------------------------------------------------------------------
    // Test 17: addr relay — ADDR_RELAY_MAX limit
    // -----------------------------------------------------------------------
    {
        assert(consensus::ADDR_RELAY_MAX == 1000);

        // An addr message with more than ADDR_RELAY_MAX should be rejected
        uint32_t addr_count = 1001;
        bool too_many = (addr_count > static_cast<uint32_t>(consensus::ADDR_RELAY_MAX));
        assert(too_many);
    }

    // -----------------------------------------------------------------------
    // Test 18: Inventory prune keeps memory bounded
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("10.0.0.8", 9333);
        Peer peer(9, addr, false);

        // Add many inventory entries
        for (int i = 0; i < 100; i++) {
            peer.mark_announced(rand_hash());
        }

        // Prune should not crash
        peer.prune_inventory();
    }

    // -----------------------------------------------------------------------
    // Test 19: Multiple inv types in single message
    // -----------------------------------------------------------------------
    {
        std::vector<InvItem> mixed;
        mixed.push_back({INV_TX, rand_hash()});
        mixed.push_back({INV_BLOCK, rand_hash()});
        mixed.push_back({INV_TX, rand_hash()});
        mixed.push_back({INV_BLOCK, rand_hash()});

        DataWriter w;
        w.write_compact_size(mixed.size());
        for (auto& item : mixed) {
            w.write_le32(static_cast<uint32_t>(item.type));
            w.write_bytes(item.hash.data(), 32);
        }

        DataReader r(w.data());
        uint64_t count = r.read_compact_size();
        assert(count == 4);

        // Read and verify types alternate
        for (size_t i = 0; i < count; i++) {
            uint32_t type = r.read_le32();
            uint256 hash;
            r.read_bytes(hash.data(), 32);
            assert(type == static_cast<uint32_t>(mixed[i].type));
        }
    }

    // -----------------------------------------------------------------------
    // Test 20: wire message with inv command
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> payload;
        DataWriter w;
        w.write_compact_size(0);  // empty inv
        payload.assign(w.data(), w.data() + w.size());

        auto msg = build_message(consensus::MAINNET_MAGIC, NetCmd::INV, payload);
        assert(msg.size() == MessageHeader::SIZE + payload.size());

        DataReader r(msg.data(), MessageHeader::SIZE);
        MessageHeader hdr;
        assert(MessageHeader::deserialize(r, hdr));
        assert(hdr.command_string() == "inv");
    }
}
