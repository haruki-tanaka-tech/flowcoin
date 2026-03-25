// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Benchmarks for chain operations: UTXO add/remove/lookup,
// block serialization/deserialization, Merkle root computation,
// and CompactSize encoding/decoding.

#include "bench.h"
#include "chain/utxo.h"
#include "hash/keccak.h"
#include "hash/merkle.h"
#include "primitives/block.h"
#include "primitives/compact.h"
#include "primitives/transaction.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <unistd.h>
#include <vector>

namespace {

// Create a temporary UTXO database path
static std::string temp_utxo_path() {
    char tmpl[] = "/tmp/flowbench_utxo_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd >= 0) close(fd);
    return std::string(tmpl);
}

// Create a synthetic UTXO entry
static flow::UTXOEntry make_entry(int i) {
    flow::UTXOEntry entry{};
    entry.value = 50'00000000LL + i;
    entry.height = static_cast<uint64_t>(i);
    entry.is_coinbase = (i % 10 == 0);
    std::memset(entry.pubkey_hash.data(), static_cast<int>(i & 0xFF), 32);
    return entry;
}

// Create a deterministic uint256 from an integer
static flow::uint256 make_hash(uint32_t n) {
    uint8_t buf[32];
    std::memset(buf, 0, 32);
    std::memcpy(buf, &n, 4);
    return flow::keccak256(buf, 32);
}

// Build a synthetic block header
static flow::CBlockHeader make_header(int height) {
    flow::CBlockHeader h;
    std::memset(h.prev_hash.data(), static_cast<int>(height & 0xFF), 32);
    std::memset(h.merkle_root.data(), 0xAB, 32);
    std::memset(h.training_hash.data(), 0xCD, 32);
    std::memset(h.dataset_hash.data(), 0xEF, 32);
    h.height = static_cast<uint64_t>(height);
    h.timestamp = 1700000000 + height * 600;
    h.nbits = 0x1f00ffff;
    h.val_loss = 5.0f;
    h.prev_val_loss = 5.1f;
    h.d_model = 512;
    h.n_layers = 8;
    h.d_ff = 1024;
    h.n_heads = 8;
    h.gru_dim = 512;
    h.n_slots = 1024;
    h.reserved_field = 0;
    h.stagnation = 0;
    h.delta_offset = 0;
    h.delta_length = 0;
    h.sparse_count = 0;
    h.sparse_threshold = 0.001f;
    h.nonce = static_cast<uint32_t>(height);
    h.version = 1;
    std::memset(h.miner_pubkey.data(), 0x55, 32);
    std::memset(h.miner_sig.data(), 0x77, 64);
    return h;
}

// Build a synthetic transaction
static flow::CTransaction make_tx(int idx) {
    flow::CTransaction tx;
    tx.version = 1;
    tx.locktime = 0;

    flow::CTxIn input;
    input.prevout.txid = make_hash(static_cast<uint32_t>(idx));
    input.prevout.index = 0;
    std::memset(input.pubkey.data(), static_cast<int>(idx & 0xFF), 32);
    std::memset(input.signature.data(), static_cast<int>((idx + 1) & 0xFF), 64);
    tx.vin.push_back(input);

    flow::CTxOut output;
    output.amount = 49'99990000LL;
    std::memset(output.pubkey_hash.data(), static_cast<int>((idx + 2) & 0xFF), 32);
    tx.vout.push_back(output);

    return tx;
}

} // namespace

namespace flow::bench {

// ===========================================================================
// UTXO operations
// ===========================================================================

BENCH(UTXO_Add) {
    auto path = temp_utxo_path();
    {
        UTXOSet utxo(path);
        utxo.begin_transaction();
        for (int i = 0; i < _iterations; i++) {
            uint256 txid = make_hash(static_cast<uint32_t>(i));
            UTXOEntry entry = make_entry(i);
            utxo.add(txid, 0, entry);
        }
        utxo.commit_transaction();
    }
    std::filesystem::remove(path);
}

BENCH(UTXO_Lookup) {
    auto path = temp_utxo_path();
    {
        UTXOSet utxo(path);
        // Pre-populate
        int count = std::min(_iterations, 10000);
        utxo.begin_transaction();
        std::vector<uint256> txids(count);
        for (int i = 0; i < count; i++) {
            txids[i] = make_hash(static_cast<uint32_t>(i));
            utxo.add(txids[i], 0, make_entry(i));
        }
        utxo.commit_transaction();

        // Benchmark lookups
        for (int i = 0; i < _iterations; i++) {
            UTXOEntry entry;
            utxo.get(txids[i % count], 0, entry);
        }
    }
    std::filesystem::remove(path);
}

BENCH(UTXO_Remove) {
    auto path = temp_utxo_path();
    {
        UTXOSet utxo(path);
        int count = std::min(_iterations, 10000);
        utxo.begin_transaction();
        std::vector<uint256> txids(count);
        for (int i = 0; i < count; i++) {
            txids[i] = make_hash(static_cast<uint32_t>(i));
            utxo.add(txids[i], 0, make_entry(i));
        }
        utxo.commit_transaction();

        utxo.begin_transaction();
        for (int i = 0; i < _iterations; i++) {
            utxo.remove(txids[i % count], 0);
        }
        utxo.commit_transaction();
    }
    std::filesystem::remove(path);
}

BENCH(UTXO_Exists) {
    auto path = temp_utxo_path();
    {
        UTXOSet utxo(path);
        int count = std::min(_iterations, 10000);
        utxo.begin_transaction();
        std::vector<uint256> txids(count);
        for (int i = 0; i < count; i++) {
            txids[i] = make_hash(static_cast<uint32_t>(i));
            utxo.add(txids[i], 0, make_entry(i));
        }
        utxo.commit_transaction();

        for (int i = 0; i < _iterations; i++) {
            bool found = utxo.exists(txids[i % count], 0);
            (void)found;
        }
    }
    std::filesystem::remove(path);
}

// ===========================================================================
// Block header serialization
// ===========================================================================

BENCH(BlockHeader_Serialize) {
    CBlockHeader h = make_header(100);
    for (int i = 0; i < _iterations; i++) {
        auto data = h.serialize();
        if (data.size() != BLOCK_HEADER_SIZE) break;
    }
}

BENCH(BlockHeader_Deserialize) {
    CBlockHeader h = make_header(100);
    auto data = h.serialize();
    for (int i = 0; i < _iterations; i++) {
        CBlockHeader h2;
        bool ok = h2.deserialize(data.data(), data.size());
        if (!ok) break;
    }
}

BENCH(BlockHeader_GetHash) {
    CBlockHeader h = make_header(100);
    for (int i = 0; i < _iterations; i++) {
        uint256 hash = h.get_hash();
        (void)hash;
    }
}

// ===========================================================================
// Full block serialization
// ===========================================================================

BENCH(Block_Serialize_10Tx) {
    CBlock block(make_header(100));
    for (int j = 0; j < 10; j++) {
        block.vtx.push_back(make_tx(j));
    }
    for (int i = 0; i < _iterations; i++) {
        auto data = block.serialize();
        if (data.empty()) break;
    }
}

BENCH(Block_Deserialize_10Tx) {
    CBlock block(make_header(100));
    for (int j = 0; j < 10; j++) {
        block.vtx.push_back(make_tx(j));
    }
    auto data = block.serialize();
    for (int i = 0; i < _iterations; i++) {
        CBlock b2;
        bool ok = b2.deserialize(data.data(), data.size());
        if (!ok) break;
    }
}

BENCH(Block_Serialize_100Tx) {
    CBlock block(make_header(100));
    for (int j = 0; j < 100; j++) {
        block.vtx.push_back(make_tx(j));
    }
    for (int i = 0; i < _iterations; i++) {
        auto data = block.serialize();
        if (data.empty()) break;
    }
}

// ===========================================================================
// Transaction serialization
// ===========================================================================

BENCH(Transaction_Serialize) {
    CTransaction tx = make_tx(42);
    for (int i = 0; i < _iterations; i++) {
        auto data = tx.serialize();
        if (data.empty()) break;
    }
}

BENCH(Transaction_Deserialize) {
    CTransaction tx = make_tx(42);
    auto data = tx.serialize();
    for (int i = 0; i < _iterations; i++) {
        CTransaction tx2;
        bool ok = tx2.deserialize(data);
        if (!ok) break;
    }
}

BENCH(Transaction_GetTxid) {
    CTransaction tx = make_tx(42);
    for (int i = 0; i < _iterations; i++) {
        uint256 txid = tx.get_txid();
        (void)txid;
    }
}

// ===========================================================================
// CompactSize encoding/decoding
// ===========================================================================

BENCH(CompactSize_Encode_Small) {
    uint8_t buf[9];
    for (int i = 0; i < _iterations; i++) {
        CompactSize::encode(static_cast<uint64_t>(i & 0xFF), buf);
    }
}

BENCH(CompactSize_Encode_Medium) {
    uint8_t buf[9];
    for (int i = 0; i < _iterations; i++) {
        CompactSize::encode(static_cast<uint64_t>(i + 1000), buf);
    }
}

BENCH(CompactSize_Encode_Large) {
    uint8_t buf[9];
    for (int i = 0; i < _iterations; i++) {
        CompactSize::encode(static_cast<uint64_t>(i) + 0x100000000ULL, buf);
    }
}

BENCH(CompactSize_Decode) {
    uint8_t buf[9];
    CompactSize::encode(12345, buf);
    for (int i = 0; i < _iterations; i++) {
        uint64_t value;
        CompactSize::decode(buf, 9, value);
        (void)value;
    }
}

BENCH(CompactSize_RoundTrip) {
    for (int i = 0; i < _iterations; i++) {
        uint64_t original = static_cast<uint64_t>(i * 997 + 1);
        uint8_t buf[9];
        size_t written = CompactSize::encode(original, buf);
        uint64_t decoded;
        CompactSize::decode(buf, written, decoded);
        if (decoded != original) break;
    }
}

// ===========================================================================
// CompactSize vector encode/decode
// ===========================================================================

BENCH(CompactSize_EncodeTo_Vector) {
    for (int i = 0; i < _iterations; i++) {
        std::vector<uint8_t> out;
        out.reserve(64);
        for (int j = 0; j < 10; j++) {
            CompactSize::encode_to(static_cast<uint64_t>(j * 1000 + i), out);
        }
        if (out.empty()) break;
    }
}

BENCH(CompactSize_DecodeFrom_Vector) {
    std::vector<uint8_t> encoded;
    for (int j = 0; j < 10; j++) {
        CompactSize::encode_to(static_cast<uint64_t>(j * 1000 + 42), encoded);
    }

    for (int i = 0; i < _iterations; i++) {
        size_t offset = 0;
        for (int j = 0; j < 10; j++) {
            uint64_t value;
            CompactSize::decode_from(encoded, offset, value);
            (void)value;
        }
        if (offset == 0) break;
    }
}

BENCH(CompactSize_EncodedSize) {
    for (int i = 0; i < _iterations; i++) {
        size_t s1 = CompactSize::encoded_size(0);
        size_t s2 = CompactSize::encoded_size(252);
        size_t s3 = CompactSize::encoded_size(253);
        size_t s4 = CompactSize::encoded_size(0xFFFF);
        size_t s5 = CompactSize::encoded_size(0x10000);
        size_t s6 = CompactSize::encoded_size(0xFFFFFFFF);
        size_t s7 = CompactSize::encoded_size(0x100000000ULL);
        (void)(s1 + s2 + s3 + s4 + s5 + s6 + s7);
    }
}

// ===========================================================================
// Block weight computation
// ===========================================================================

BENCH(Block_GetWeight_10Tx) {
    CBlock block(make_header(100));
    for (int j = 0; j < 10; j++) {
        block.vtx.push_back(make_tx(j));
    }
    for (int i = 0; i < _iterations; i++) {
        size_t w = block.get_block_weight();
        if (w == 0) break;
    }
}

BENCH(Block_GetBlockSize_100Tx) {
    CBlock block(make_header(100));
    for (int j = 0; j < 100; j++) {
        block.vtx.push_back(make_tx(j));
    }
    for (int i = 0; i < _iterations; i++) {
        size_t s = block.get_block_size();
        if (s == 0) break;
    }
}

// ===========================================================================
// Block header hash comparison
// ===========================================================================

BENCH(BlockHeader_GetTrainingHash) {
    CBlockHeader h = make_header(100);
    for (int i = 0; i < _iterations; i++) {
        uint256 hash = h.get_training_hash();
        (void)hash;
    }
}

BENCH(BlockHeader_GetUnsignedData) {
    CBlockHeader h = make_header(100);
    for (int i = 0; i < _iterations; i++) {
        auto data = h.get_unsigned_data();
        if (data.size() != BLOCK_HEADER_UNSIGNED_SIZE) break;
    }
}

BENCH(BlockHeader_GetHashHex) {
    CBlockHeader h = make_header(100);
    for (int i = 0; i < _iterations; i++) {
        std::string hex = h.get_hash_hex();
        if (hex.empty()) break;
    }
}

// ===========================================================================
// Transaction outpoint operations
// ===========================================================================

BENCH(COutPoint_Serialize) {
    COutPoint op(make_hash(42), 7);
    for (int i = 0; i < _iterations; i++) {
        auto data = op.serialize();
        if (data.empty()) break;
    }
}

BENCH(COutPoint_Comparison) {
    COutPoint a(make_hash(1), 0);
    COutPoint b(make_hash(2), 0);
    for (int i = 0; i < _iterations; i++) {
        bool lt = a < b;
        bool eq = a == b;
        (void)(lt || eq);
    }
}

// ===========================================================================
// Transaction multi-input/output
// ===========================================================================

BENCH(Transaction_Serialize_5in_3out) {
    CTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    for (int j = 0; j < 5; j++) {
        CTxIn input;
        input.prevout = COutPoint(make_hash(static_cast<uint32_t>(j)), 0);
        std::memset(input.pubkey.data(), static_cast<int>(j + 1), 32);
        std::memset(input.signature.data(), static_cast<int>(j + 10), 64);
        tx.vin.push_back(input);
    }
    for (int j = 0; j < 3; j++) {
        CTxOut output;
        output.amount = 10'00000000LL * (j + 1);
        std::memset(output.pubkey_hash.data(), static_cast<int>(j + 100), 32);
        tx.vout.push_back(output);
    }
    for (int i = 0; i < _iterations; i++) {
        auto data = tx.serialize();
        if (data.empty()) break;
    }
}

BENCH(Transaction_SerializeForHash) {
    CTransaction tx = make_tx(42);
    for (int i = 0; i < _iterations; i++) {
        auto data = tx.serialize_for_hash();
        if (data.empty()) break;
    }
}

// ===========================================================================
// UTXO balance query
// ===========================================================================

BENCH(UTXO_GetBalance) {
    auto path = temp_utxo_path();
    {
        UTXOSet utxo(path);
        int count = 500;
        std::array<uint8_t, 32> target_hash;
        std::memset(target_hash.data(), 0xAA, 32);

        utxo.begin_transaction();
        for (int i = 0; i < count; i++) {
            uint256 txid = make_hash(static_cast<uint32_t>(i));
            UTXOEntry entry{};
            entry.value = 50'00000000LL;
            entry.height = 100;
            entry.is_coinbase = false;
            // Half go to target, half elsewhere
            if (i % 2 == 0) {
                entry.pubkey_hash = target_hash;
            } else {
                std::memset(entry.pubkey_hash.data(), static_cast<int>(i & 0xFF), 32);
            }
            utxo.add(txid, 0, entry);
        }
        utxo.commit_transaction();

        for (int i = 0; i < _iterations; i++) {
            Amount bal = utxo.get_balance(target_hash);
            (void)bal;
        }
    }
    std::filesystem::remove(path);
}

// ===========================================================================
// UTXO statistics
// ===========================================================================

BENCH(UTXO_TotalCount) {
    auto path = temp_utxo_path();
    {
        UTXOSet utxo(path);
        utxo.begin_transaction();
        for (int i = 0; i < 500; i++) {
            uint256 txid = make_hash(static_cast<uint32_t>(i));
            utxo.add(txid, 0, make_entry(i));
        }
        utxo.commit_transaction();

        for (int i = 0; i < _iterations; i++) {
            size_t count = utxo.total_count();
            (void)count;
        }
    }
    std::filesystem::remove(path);
}

BENCH(UTXO_TotalValue) {
    auto path = temp_utxo_path();
    {
        UTXOSet utxo(path);
        utxo.begin_transaction();
        for (int i = 0; i < 500; i++) {
            uint256 txid = make_hash(static_cast<uint32_t>(i));
            utxo.add(txid, 0, make_entry(i));
        }
        utxo.commit_transaction();

        for (int i = 0; i < _iterations; i++) {
            Amount val = utxo.total_value();
            (void)val;
        }
    }
    std::filesystem::remove(path);
}

} // namespace flow::bench
