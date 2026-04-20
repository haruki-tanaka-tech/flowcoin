// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Benchmarks for the transaction mempool: add_transaction throughput,
// fee-rate sorting, ancestor computation, and large-pool operations.

#include "bench.h"
#include "chain/utxo.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "mempool/mempool.h"
#include "primitives/transaction.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <unistd.h>
#include <vector>

namespace {

static std::string temp_db_path() {
    char tmpl[] = "/tmp/flowbench_mp_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd >= 0) close(fd);
    return std::string(tmpl);
}

static flow::uint256 make_hash(uint32_t n) {
    uint8_t buf[32];
    std::memset(buf, 0, 32);
    std::memcpy(buf, &n, 4);
    return flow::keccak256(buf, 32);
}

// Create a funded UTXO set with N entries and matching transactions
struct TestContext {
    std::string db_path;
    std::unique_ptr<flow::UTXOSet> utxo;
    std::vector<flow::KeyPair> keys;
    std::vector<flow::uint256> txids;

    TestContext(int n_utxos) {
        db_path = temp_db_path();
        utxo = std::make_unique<flow::UTXOSet>(db_path);
        keys.resize(n_utxos);
        txids.resize(n_utxos);

        utxo->begin_transaction();
        for (int i = 0; i < n_utxos; i++) {
            keys[i] = flow::generate_keypair();
            txids[i] = make_hash(static_cast<uint32_t>(i));

            flow::uint256 pubkey_hash = flow::keccak256d(keys[i].pubkey.data(), 32);
            flow::UTXOEntry entry{};
            entry.value = 100'00000000LL;
            std::memcpy(entry.pubkey_hash.data(), pubkey_hash.data(), 32);
            entry.height = 100;
            entry.is_coinbase = false;

            utxo->add(txids[i], 0, entry);
        }
        utxo->commit_transaction();
    }

    ~TestContext() {
        utxo.reset();
        std::filesystem::remove(db_path);
    }

    // Build a transaction spending UTXO at index
    flow::CTransaction build_tx(int idx, flow::Amount fee = 10000) const {
        flow::CTransaction tx;
        tx.version = 1;
        tx.locktime = 0;

        flow::CTxIn input;
        input.prevout.txid = txids[idx];
        input.prevout.index = 0;
        std::memcpy(input.pubkey.data(), keys[idx].pubkey.data(), 32);

        // Sign the transaction
        auto hash_data = tx.serialize_for_hash();
        flow::uint256 sighash = flow::keccak256d(hash_data.data(), hash_data.size());
        auto sig = flow::ed25519_sign_hash(sighash.data(),
                                            keys[idx].privkey.data(),
                                            keys[idx].pubkey.data());
        std::memcpy(input.signature.data(), sig.data(), 64);
        tx.vin.push_back(input);

        flow::CTxOut output;
        output.amount = 100'00000000LL - fee;
        flow::uint256 out_hash = flow::keccak256d(keys[(idx + 1) % static_cast<int>(keys.size())].pubkey.data(), 32);
        std::memcpy(output.pubkey_hash.data(), out_hash.data(), 32);
        tx.vout.push_back(output);

        return tx;
    }
};

} // namespace

namespace flow::bench {

// ===========================================================================
// Mempool add
// ===========================================================================

BENCH(Mempool_Add_Sequential) {
    int count = std::min(_iterations, 5000);
    TestContext ctx(count);
    Mempool pool(*ctx.utxo);

    for (int i = 0; i < count; i++) {
        CTransaction tx = ctx.build_tx(i);
        auto result = pool.add_transaction(tx);
        (void)result;
    }
}

// ===========================================================================
// Mempool lookup
// ===========================================================================

BENCH(Mempool_Exists) {
    int count = std::min(_iterations, 2000);
    TestContext ctx(count);
    Mempool pool(*ctx.utxo);

    // Pre-populate
    std::vector<uint256> inserted_txids;
    for (int i = 0; i < count; i++) {
        CTransaction tx = ctx.build_tx(i);
        pool.add_transaction(tx);
        inserted_txids.push_back(tx.get_txid());
    }

    // Benchmark lookups
    for (int i = 0; i < _iterations; i++) {
        bool found = pool.exists(inserted_txids[i % count]);
        (void)found;
    }
}

BENCH(Mempool_Get) {
    int count = std::min(_iterations, 2000);
    TestContext ctx(count);
    Mempool pool(*ctx.utxo);

    std::vector<uint256> inserted_txids;
    for (int i = 0; i < count; i++) {
        CTransaction tx = ctx.build_tx(i);
        pool.add_transaction(tx);
        inserted_txids.push_back(tx.get_txid());
    }

    for (int i = 0; i < _iterations; i++) {
        CTransaction tx;
        pool.get(inserted_txids[i % count], tx);
    }
}

// ===========================================================================
// Fee-rate sorting
// ===========================================================================

BENCH(Mempool_GetSorted_100) {
    TestContext ctx(100);
    Mempool pool(*ctx.utxo);

    for (int i = 0; i < 100; i++) {
        CTransaction tx = ctx.build_tx(i, 10000 + i * 100);
        pool.add_transaction(tx);
    }

    for (int i = 0; i < _iterations; i++) {
        auto sorted = pool.get_sorted_transactions(100);
        if (sorted.empty()) break;
    }
}

BENCH(Mempool_GetSorted_1000) {
    int count = std::min(1000, 1000);
    TestContext ctx(count);
    Mempool pool(*ctx.utxo);

    for (int i = 0; i < count; i++) {
        CTransaction tx = ctx.build_tx(i, 10000 + i * 50);
        pool.add_transaction(tx);
    }

    for (int i = 0; i < _iterations; i++) {
        auto sorted = pool.get_sorted_transactions(1000);
        if (sorted.empty()) break;
    }
}

// ===========================================================================
// Mempool removal
// ===========================================================================

BENCH(Mempool_Remove) {
    int count = std::min(_iterations, 2000);
    TestContext ctx(count);
    Mempool pool(*ctx.utxo);

    std::vector<uint256> inserted_txids;
    for (int i = 0; i < count; i++) {
        CTransaction tx = ctx.build_tx(i);
        pool.add_transaction(tx);
        inserted_txids.push_back(tx.get_txid());
    }

    for (int i = 0; i < count; i++) {
        pool.remove(inserted_txids[i]);
    }
}

// ===========================================================================
// Mempool statistics
// ===========================================================================

BENCH(Mempool_Size) {
    TestContext ctx(500);
    Mempool pool(*ctx.utxo);

    for (int i = 0; i < 500; i++) {
        CTransaction tx = ctx.build_tx(i);
        pool.add_transaction(tx);
    }

    for (int i = 0; i < _iterations; i++) {
        size_t s = pool.size();
        size_t b = pool.total_bytes();
        (void)s;
        (void)b;
    }
}

BENCH(Mempool_GetTxids) {
    TestContext ctx(500);
    Mempool pool(*ctx.utxo);

    for (int i = 0; i < 500; i++) {
        CTransaction tx = ctx.build_tx(i);
        pool.add_transaction(tx);
    }

    for (int i = 0; i < _iterations; i++) {
        auto txids = pool.get_txids();
        if (txids.empty()) break;
    }
}

} // namespace flow::bench
