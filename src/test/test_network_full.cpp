// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for wire protocol message encoding/decoding: message headers,
// checksum verification, magic bytes, version messages, block/transaction
// serialization, inv/getdata encoding, and address messages.

#include "net/protocol.h"
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
#include <vector>

using namespace flow;

void test_network_full() {
    // -----------------------------------------------------------------------
    // Test 1: Message header serialization/deserialization
    // -----------------------------------------------------------------------
    {
        MessageHeader hdr;
        hdr.magic = consensus::MAINNET_MAGIC;
        std::memset(hdr.command, 0, 12);
        std::strncpy(hdr.command, "version", 12);
        hdr.payload_size = 1234;
        hdr.checksum = 0xDEADBEEF;

        DataWriter w;
        hdr.serialize(w);
        assert(w.size() == MessageHeader::SIZE);  // 24 bytes

        DataReader r(w.data());
        MessageHeader restored;
        assert(MessageHeader::deserialize(r, restored));
        assert(restored.magic == consensus::MAINNET_MAGIC);
        assert(restored.command_string() == "version");
        assert(restored.payload_size == 1234);
        assert(restored.checksum == 0xDEADBEEF);
    }

    // -----------------------------------------------------------------------
    // Test 2: Message checksum verification
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05};
        uint32_t checksum = compute_checksum(payload.data(), payload.size());

        // Checksum should be first 4 bytes of keccak256(payload)
        uint256 hash = keccak256(payload.data(), payload.size());
        uint32_t expected;
        std::memcpy(&expected, hash.data(), 4);
        assert(checksum == expected);

        // Different payload → different checksum
        std::vector<uint8_t> payload2 = {0x06, 0x07, 0x08};
        uint32_t checksum2 = compute_checksum(payload2.data(), payload2.size());
        assert(checksum != checksum2);
    }

    // -----------------------------------------------------------------------
    // Test 3: Empty payload checksum
    // -----------------------------------------------------------------------
    {
        uint32_t checksum = compute_checksum(nullptr, 0);
        // Should be first 4 bytes of keccak256("")
        uint256 hash = keccak256(nullptr, 0);
        uint32_t expected;
        std::memcpy(&expected, hash.data(), 4);
        assert(checksum == expected);
    }

    // -----------------------------------------------------------------------
    // Test 4: Magic bytes correct per network
    // -----------------------------------------------------------------------
    {
        assert(consensus::MAINNET_MAGIC == 0x464C4F57);   // "FLOW"
        assert(consensus::TESTNET_MAGIC == 0x54464C57);   // "TFLW"
        assert(consensus::REGTEST_MAGIC == 0x52464C57);   // "RFLW"

        // All different
        assert(consensus::MAINNET_MAGIC != consensus::TESTNET_MAGIC);
        assert(consensus::MAINNET_MAGIC != consensus::REGTEST_MAGIC);
        assert(consensus::TESTNET_MAGIC != consensus::REGTEST_MAGIC);
    }

    // -----------------------------------------------------------------------
    // Test 5: build_message constructs header + payload
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> payload = {0xAA, 0xBB, 0xCC};
        auto msg = build_message(consensus::MAINNET_MAGIC, "ping", payload);

        // Should be 24 (header) + 3 (payload) = 27 bytes
        assert(msg.size() == 27);

        // Parse header back
        DataReader r(msg.data(), 24);
        MessageHeader hdr;
        assert(MessageHeader::deserialize(r, hdr));
        assert(hdr.magic == consensus::MAINNET_MAGIC);
        assert(hdr.command_string() == "ping");
        assert(hdr.payload_size == 3);

        // Verify checksum
        uint32_t expected_checksum = compute_checksum(payload.data(), payload.size());
        assert(hdr.checksum == expected_checksum);

        // Verify payload bytes
        assert(msg[24] == 0xAA);
        assert(msg[25] == 0xBB);
        assert(msg[26] == 0xCC);
    }

    // -----------------------------------------------------------------------
    // Test 6: build_message with empty payload
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> empty_payload;
        auto msg = build_message(consensus::MAINNET_MAGIC, "verack", empty_payload);
        assert(msg.size() == 24);

        DataReader r(msg.data(), 24);
        MessageHeader hdr;
        assert(MessageHeader::deserialize(r, hdr));
        assert(hdr.payload_size == 0);
        assert(hdr.command_string() == "verack");
    }

    // -----------------------------------------------------------------------
    // Test 7: Version message serialization/deserialization round-trip
    // -----------------------------------------------------------------------
    {
        VersionMessage ver;
        ver.protocol_version = consensus::PROTOCOL_VERSION;
        ver.services = NODE_NETWORK;
        ver.timestamp = 1700000000;
        ver.addr_recv = CNetAddr("192.168.1.1", 9333);
        ver.addr_from = CNetAddr("10.0.0.1", 9333);
        ver.nonce = 0x1234567890ABCDEFULL;
        ver.user_agent = "/FlowCoin:0.1.0/";
        ver.start_height = 12345;

        auto serialized = ver.serialize();
        assert(!serialized.empty());

        VersionMessage restored;
        assert(VersionMessage::deserialize(serialized.data(), serialized.size(), restored));

        assert(restored.protocol_version == consensus::PROTOCOL_VERSION);
        assert(restored.services == NODE_NETWORK);
        assert(restored.timestamp == 1700000000);
        assert(restored.nonce == 0x1234567890ABCDEFULL);
        assert(restored.user_agent == "/FlowCoin:0.1.0/");
        assert(restored.start_height == 12345);
    }

    // -----------------------------------------------------------------------
    // Test 8: CNetAddr IPv4 construction and serialization
    // -----------------------------------------------------------------------
    {
        CNetAddr addr("192.168.1.100", 9333);
        assert(addr.is_ipv4());
        assert(addr.port == 9333);

        std::string s = addr.to_string();
        assert(s.find("192.168.1.100") != std::string::npos);
        assert(s.find("9333") != std::string::npos);

        // Serialize and restore
        DataWriter w;
        addr.serialize(w);

        DataReader r(w.data());
        CNetAddr restored = CNetAddr::deserialize(r);
        assert(restored == addr);
        assert(restored.port == 9333);
    }

    // -----------------------------------------------------------------------
    // Test 9: CNetAddr IPv6 handling
    // -----------------------------------------------------------------------
    {
        CNetAddr addr;
        addr.ip[0] = 0x20;
        addr.ip[1] = 0x01;
        addr.ip[2] = 0x0d;
        addr.ip[3] = 0xb8;
        addr.port = 8080;

        assert(!addr.is_ipv4());

        DataWriter w;
        addr.serialize(w);
        DataReader r(w.data());
        CNetAddr restored = CNetAddr::deserialize(r);
        assert(restored == addr);
    }

    // -----------------------------------------------------------------------
    // Test 10: Block message serialization round-trip
    // -----------------------------------------------------------------------
    {
        CBlock block;
        block.version = 1;
        block.height = 100;
        block.timestamp = 1700000000;
        block.nbits = consensus::INITIAL_NBITS;
        block.nonce = 42;
        // Add a coinbase transaction
        CTransaction cb;
        cb.version = 1;
        CTxIn cb_in;
        cb.vin.push_back(cb_in);
        auto kp = generate_keypair();
        auto pkh = keccak256(kp.pubkey.data(), 32);
        std::array<uint8_t, 32> pkh_arr;
        std::memcpy(pkh_arr.data(), pkh.data(), 32);
        cb.vout.push_back(CTxOut(50 * COIN, pkh_arr));
        block.vtx.push_back(cb);

        auto serialized = block.serialize();
        assert(!serialized.empty());

        CBlock restored;
        assert(restored.deserialize(serialized));
        assert(restored.version == 1);
        assert(restored.height == 100);
        assert(restored.vtx.size() == 1);
        assert(restored.vtx[0].is_coinbase());
    }

    // -----------------------------------------------------------------------
    // Test 11: Transaction message round-trip
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;

        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 0);
        auto kp = generate_keypair();
        std::memcpy(in.pubkey.data(), kp.pubkey.data(), 32);
        tx.vin.push_back(in);

        auto kp_dest = generate_keypair();
        auto pkh = keccak256(kp_dest.pubkey.data(), 32);
        std::array<uint8_t, 32> pkh_arr;
        std::memcpy(pkh_arr.data(), pkh.data(), 32);
        tx.vout.push_back(CTxOut(10 * COIN, pkh_arr));

        auto serialized = tx.serialize();
        assert(!serialized.empty());

        CTransaction restored;
        assert(restored.deserialize(serialized));
        assert(restored.version == 1);
        assert(restored.vin.size() == 1);
        assert(restored.vout.size() == 1);
        assert(restored.vin[0].prevout.txid == prev);
        assert(restored.vout[0].amount == 10 * COIN);
    }

    // -----------------------------------------------------------------------
    // Test 12: Block header serialization round-trip
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr;
        hdr.version = 1;
        hdr.height = 42;
        hdr.timestamp = 1700000000;
        hdr.nbits = 0x1f00ffff;
        hdr.nonce = 123;
        auto serialized = hdr.serialize();
        assert(serialized.size() == BLOCK_HEADER_SIZE);

        CBlockHeader restored;
        assert(restored.deserialize(serialized.data(), serialized.size()));
        assert(restored.version == 1);
        assert(restored.height == 42);
        assert(restored.timestamp == 1700000000);
        assert(restored.nbits == 0x1f00ffff);
        assert(restored.nonce == 123);
    }

    // -----------------------------------------------------------------------
    // Test 13: Multiple block headers (simulated headers message)
    // -----------------------------------------------------------------------
    {
        std::vector<CBlockHeader> headers;
        for (int i = 0; i < 5; ++i) {
            CBlockHeader h;
            h.version = 1;
            h.height = static_cast<uint64_t>(i);
            h.timestamp = 1700000000 + i * 600;
            h.nbits = consensus::INITIAL_NBITS;
            headers.push_back(h);
        }

        // Serialize all headers
        DataWriter w;
        w.write_compact_size(headers.size());
        for (const auto& h : headers) {
            auto data = h.serialize();
            w.write_bytes(data.data(), data.size());
        }

        // Deserialize
        DataReader r(w.data());
        uint64_t count = r.read_compact_size();
        assert(count == 5);

        for (uint64_t i = 0; i < count; ++i) {
            // Read BLOCK_HEADER_SIZE bytes
            std::vector<uint8_t> hdr_data(BLOCK_HEADER_SIZE);
            r.read_bytes_into(hdr_data.data(), BLOCK_HEADER_SIZE);
            assert(!r.error());

            CBlockHeader h;
            assert(h.deserialize(hdr_data.data(), hdr_data.size()));
            assert(h.height == i);
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: InvItem encoding
    // -----------------------------------------------------------------------
    {
        InvItem item;
        item.type = INV_TX;
        item.hash = GetRandUint256();

        DataWriter w;
        w.write_u32_le(static_cast<uint32_t>(item.type));
        w.write_bytes(item.hash.data(), 32);
        assert(w.size() == 36);

        DataReader r(w.data());
        uint32_t type = r.read_u32_le();
        uint256 hash;
        r.read_bytes_into(hash.data(), 32);
        assert(type == INV_TX);
        assert(hash == item.hash);
    }

    // -----------------------------------------------------------------------
    // Test 15: Multiple InvItems (inv/getdata message)
    // -----------------------------------------------------------------------
    {
        std::vector<InvItem> items;
        for (int i = 0; i < 10; ++i) {
            InvItem item;
            item.type = (i % 2 == 0) ? INV_TX : INV_BLOCK;
            item.hash = GetRandUint256();
            items.push_back(item);
        }

        DataWriter w;
        w.write_compact_size(items.size());
        for (const auto& item : items) {
            w.write_u32_le(static_cast<uint32_t>(item.type));
            w.write_bytes(item.hash.data(), 32);
        }

        DataReader r(w.data());
        uint64_t count = r.read_compact_size();
        assert(count == 10);

        for (uint64_t i = 0; i < count; ++i) {
            uint32_t type = r.read_u32_le();
            uint256 hash;
            r.read_bytes_into(hash.data(), 32);
            assert(type == static_cast<uint32_t>(items[i].type));
            assert(hash == items[i].hash);
        }
        assert(!r.error());
    }

    // -----------------------------------------------------------------------
    // Test 16: Addr message with IPv4 addresses
    // -----------------------------------------------------------------------
    {
        std::vector<CNetAddr> addrs;
        addrs.push_back(CNetAddr("8.8.8.8", 9333));
        addrs.push_back(CNetAddr("1.1.1.1", 9333));
        addrs.push_back(CNetAddr("192.168.1.1", 9333));

        DataWriter w;
        w.write_compact_size(addrs.size());
        for (const auto& addr : addrs) {
            addr.serialize(w);
        }

        DataReader r(w.data());
        uint64_t count = r.read_compact_size();
        assert(count == 3);

        for (uint64_t i = 0; i < count; ++i) {
            CNetAddr restored = CNetAddr::deserialize(r);
            assert(restored == addrs[i]);
        }
        assert(!r.error());
    }

    // -----------------------------------------------------------------------
    // Test 17: CNetAddr equality and inequality
    // -----------------------------------------------------------------------
    {
        CNetAddr a1("192.168.1.1", 9333);
        CNetAddr a2("192.168.1.1", 9333);
        CNetAddr a3("192.168.1.2", 9333);
        CNetAddr a4("192.168.1.1", 9334);

        assert(a1 == a2);
        assert(a1 != a3);
        assert(a1 != a4);
    }

    // -----------------------------------------------------------------------
    // Test 18: Command string null-padding and extraction
    // -----------------------------------------------------------------------
    {
        MessageHeader hdr;
        std::memset(hdr.command, 0, 12);
        std::strncpy(hdr.command, "ping", 12);
        assert(hdr.command_string() == "ping");

        std::memset(hdr.command, 0, 12);
        std::strncpy(hdr.command, "getheaders", 12);
        assert(hdr.command_string() == "getheaders");

        // Max length command (12 chars, no null terminator in the field)
        std::memset(hdr.command, 0, 12);
        std::strncpy(hdr.command, "getblocktxn", 12);
        assert(hdr.command_string() == "getblocktxn");
    }

    // -----------------------------------------------------------------------
    // Test 19: Service flags
    // -----------------------------------------------------------------------
    {
        assert(NODE_NONE == 0);
        assert(NODE_NETWORK == 1);

        uint64_t services = NODE_NETWORK;
        assert((services & NODE_NETWORK) != 0);
        assert((services & 0x02) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 20: InvType values
    // -----------------------------------------------------------------------
    {
        assert(INV_TX == 1);
        assert(INV_BLOCK == 2);
    }

    // -----------------------------------------------------------------------
    // Test 21: MAX_PAYLOAD_SIZE limit
    // -----------------------------------------------------------------------
    {
        assert(MessageHeader::MAX_PAYLOAD_SIZE == 32'000'000);
    }

    // -----------------------------------------------------------------------
    // Test 22: Ports match consensus params
    // -----------------------------------------------------------------------
    {
        assert(consensus::MAINNET_PORT == 9333);
        assert(consensus::MAINNET_RPC_PORT == 9334);
        assert(consensus::TESTNET_PORT == 19333);
        assert(consensus::REGTEST_PORT == 29333);
    }

    // -----------------------------------------------------------------------
    // Test 23: Block locator serialization
    // -----------------------------------------------------------------------
    {
        CBlockLocator locator;
        for (int i = 0; i < 10; ++i) {
            locator.hashes.push_back(GetRandUint256());
        }
        assert(!locator.is_null());

        auto serialized = locator.serialize();
        assert(!serialized.empty());

        CBlockLocator restored;
        assert(restored.deserialize(serialized.data(), serialized.size()));
        assert(restored.hashes.size() == 10);

        for (int i = 0; i < 10; ++i) {
            assert(restored.hashes[i] == locator.hashes[i]);
        }
    }

    // -----------------------------------------------------------------------
    // Test 24: Empty block locator
    // -----------------------------------------------------------------------
    {
        CBlockLocator locator;
        assert(locator.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 25: CNetAddr default constructor
    // -----------------------------------------------------------------------
    {
        CNetAddr addr;
        // Default should be all zeros
        bool all_zero = true;
        for (auto b : addr.ip) {
            if (b != 0) { all_zero = false; break; }
        }
        assert(all_zero);
        assert(addr.port == 0);
    }

    // -----------------------------------------------------------------------
    // Test 26: VersionMessage with different user agents
    // -----------------------------------------------------------------------
    {
        VersionMessage v1;
        v1.protocol_version = 1;
        v1.services = NODE_NETWORK;
        v1.timestamp = 1700000000;
        v1.nonce = 42;
        v1.user_agent = "/FlowCoin:0.1.0/";
        v1.start_height = 0;

        auto s1 = v1.serialize();

        VersionMessage v2;
        v2.protocol_version = 1;
        v2.services = NODE_NETWORK;
        v2.timestamp = 1700000000;
        v2.nonce = 42;
        v2.user_agent = "/FlowCoin:2.0.0-beta/";
        v2.start_height = 0;

        auto s2 = v2.serialize();

        // Different user agents → different serialized sizes
        assert(s1.size() != s2.size());

        // Both round-trip correctly
        VersionMessage r1, r2;
        assert(VersionMessage::deserialize(s1.data(), s1.size(), r1));
        assert(VersionMessage::deserialize(s2.data(), s2.size(), r2));
        assert(r1.user_agent == "/FlowCoin:0.1.0/");
        assert(r2.user_agent == "/FlowCoin:2.0.0-beta/");
    }

    // -----------------------------------------------------------------------
    // Test 27: COutPoint serialization round-trip
    // -----------------------------------------------------------------------
    {
        uint256 txid = GetRandUint256();
        COutPoint op(txid, 42);

        auto serialized = op.serialize();
        assert(serialized.size() == 36);  // 32 + 4

        COutPoint restored;
        assert(restored.deserialize(serialized.data(), serialized.size()));
        assert(restored.txid == txid);
        assert(restored.index == 42);
    }

    // -----------------------------------------------------------------------
    // Test 28: COutPoint comparison operators
    // -----------------------------------------------------------------------
    {
        uint256 txid1, txid2;
        txid1[0] = 0x01;
        txid2[0] = 0x02;

        COutPoint a(txid1, 0);
        COutPoint b(txid1, 1);
        COutPoint c(txid2, 0);

        assert(a < b);   // same txid, different index
        assert(a < c);   // different txid
        assert(a == a);
        assert(a != b);
        assert(a <= b);
        assert(b > a);
        assert(b >= a);
    }

    // -----------------------------------------------------------------------
    // Test 29: COutPoint is_null
    // -----------------------------------------------------------------------
    {
        COutPoint null_op;
        assert(null_op.is_null());

        uint256 txid = GetRandUint256();
        COutPoint non_null(txid, 0);
        assert(!non_null.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 30: Transaction with multiple inputs/outputs serialization
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;

        for (int i = 0; i < 5; ++i) {
            CTxIn in;
            in.prevout = COutPoint(GetRandUint256(), static_cast<uint32_t>(i));
            GetRandBytes(in.pubkey.data(), 32);
            GetRandBytes(in.signature.data(), 64);
            tx.vin.push_back(in);
        }

        for (int i = 0; i < 3; ++i) {
            std::array<uint8_t, 32> pkh;
            GetRandBytes(pkh.data(), 32);
            tx.vout.push_back(CTxOut((i + 1) * COIN, pkh));
        }

        auto serialized = tx.serialize();
        CTransaction restored;
        assert(restored.deserialize(serialized));
        assert(restored.vin.size() == 5);
        assert(restored.vout.size() == 3);
        assert(restored.get_txid() == tx.get_txid());
    }

    // -----------------------------------------------------------------------
    // Test 32: Block hash is deterministic
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr;
        hdr.version = 1;
        hdr.height = 42;
        hdr.timestamp = 1700000000;
        hdr.nbits = 0x1f00ffff;

        auto hash1 = hdr.get_hash();
        auto hash2 = hdr.get_hash();
        assert(hash1 == hash2);
        assert(!hash1.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 33: Different block headers have different hashes
    // -----------------------------------------------------------------------
    {
        CBlockHeader h1, h2;
        h1.version = 1;
        h1.height = 1;
        h1.timestamp = 1700000000;

        h2.version = 1;
        h2.height = 2;
        h2.timestamp = 1700000000;

        assert(h1.get_hash() != h2.get_hash());
    }

    // -----------------------------------------------------------------------
    // Test 34: Compact size encoding in DataWriter/DataReader
    // -----------------------------------------------------------------------
    {
        // Test various compact size values
        std::vector<uint64_t> values = {0, 1, 0xFC, 0xFD, 0xFE, 0xFF, 0xFFFF,
                                         0x10000, 0xFFFFFFFF, 0x100000000ULL};
        for (uint64_t val : values) {
            DataWriter w;
            w.write_compact_size(val);

            DataReader r(w.data());
            uint64_t restored = r.read_compact_size();
            assert(!r.error());
            assert(restored == val);
        }
    }

    // -----------------------------------------------------------------------
    // Test 35: DataWriter/DataReader primitive round-trips
    // -----------------------------------------------------------------------
    {
        DataWriter w;
        w.write_u8(0xAB);
        w.write_u16_le(0x1234);
        w.write_u32_le(0xDEADBEEF);
        w.write_u64_le(0x0102030405060708ULL);
        w.write_i64_le(-12345);
        w.write_string("hello");
        w.write_bool(true);
        w.write_bool(false);

        DataReader r(w.data());
        assert(r.read_u8() == 0xAB);
        assert(r.read_u16_le() == 0x1234);
        assert(r.read_u32_le() == 0xDEADBEEF);
        assert(r.read_u64_le() == 0x0102030405060708ULL);
        assert(r.read_i64_le() == -12345);
        assert(r.read_string() == "hello");
        assert(r.read_bool() == true);
        assert(r.read_bool() == false);
        assert(!r.error());
    }

    // -----------------------------------------------------------------------
    // Test 36: Block header unsigned data is 244 bytes
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr;
        hdr.version = 1;
        auto unsigned_data = hdr.get_unsigned_data();
        assert(unsigned_data.size() == BLOCK_HEADER_UNSIGNED_SIZE);
    }

    // -----------------------------------------------------------------------
    // Test 37: Block weight calculation
    // -----------------------------------------------------------------------
    {
        CBlock block;
        block.version = 1;
        block.height = 1;

        CTransaction cb;
        cb.version = 1;
        CTxIn cb_in;
        cb.vin.push_back(cb_in);
        std::array<uint8_t, 32> pkh;
        GetRandBytes(pkh.data(), 32);
        cb.vout.push_back(CTxOut(50 * COIN, pkh));
        block.vtx.push_back(cb);

        size_t weight = block.get_block_weight();
        assert(weight > 0);

        // Header weight should be BLOCK_HEADER_SIZE * WITNESS_SCALE_FACTOR
        assert(block.get_header_weight() == BLOCK_HEADER_SIZE * WITNESS_SCALE_FACTOR);
    }

    // -----------------------------------------------------------------------
    // Test 38: CBlock::check_block verifies coinbase
    // -----------------------------------------------------------------------
    {
        CBlock good_block;
        good_block.version = 1;
        good_block.height = 1;

        // Add coinbase
        CTransaction cb;
        cb.version = 1;
        CTxIn cb_in;
        cb.vin.push_back(cb_in);
        std::array<uint8_t, 32> pkh;
        GetRandBytes(pkh.data(), 32);
        cb.vout.push_back(CTxOut(50 * COIN, pkh));
        good_block.vtx.push_back(cb);

        // Compute and set merkle root
        good_block.merkle_root = good_block.compute_merkle_root();

        bool ok = good_block.check_block();
        assert(ok);

        // Block with no transactions should fail
        CBlock empty_block;
        empty_block.version = 1;
        assert(!empty_block.check_block());
    }

    // -----------------------------------------------------------------------
    // Test 39: Protocol version constant
    // -----------------------------------------------------------------------
    {
        assert(consensus::PROTOCOL_VERSION == 1);
    }

    // -----------------------------------------------------------------------
    // Test 40: NetCmd command strings are correct
    // -----------------------------------------------------------------------
    {
        assert(std::string(NetCmd::VERSION) == "version");
        assert(std::string(NetCmd::VERACK) == "verack");
        assert(std::string(NetCmd::PING) == "ping");
        assert(std::string(NetCmd::PONG) == "pong");
        assert(std::string(NetCmd::BLOCK) == "block");
        assert(std::string(NetCmd::TX) == "tx");
        assert(std::string(NetCmd::INV) == "inv");
        assert(std::string(NetCmd::GETDATA) == "getdata");
        assert(std::string(NetCmd::HEADERS) == "headers");
        assert(std::string(NetCmd::GETHEADERS) == "getheaders");
        assert(std::string(NetCmd::GETBLOCKS) == "getblocks");
        assert(std::string(NetCmd::ADDR) == "addr");
        assert(std::string(NetCmd::GETADDR) == "getaddr");
        assert(std::string(NetCmd::REJECT) == "reject");
        assert(std::string(NetCmd::FEEFILTER) == "feefilter");
    }
}
