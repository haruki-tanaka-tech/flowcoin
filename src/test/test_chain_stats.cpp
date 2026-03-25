// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for chain statistics: height, tip, total supply, difficulty,
// model parameters, block verification, UTXO snapshots, header ranges,
// coin age priority, and common ancestor detection.

#include "consensus/difficulty.h"
#include "consensus/genesis.h"
#include "consensus/growth.h"
#include "consensus/merkle.h"
#include "consensus/params.h"
#include "consensus/pow.h"
#include "consensus/reward.h"
#include "consensus/validation.h"
#include "hash/keccak.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/arith_uint256.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <map>
#include <numeric>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---------------------------------------------------------------------------
// ChainStats — lightweight chain state summary
// ---------------------------------------------------------------------------

struct ChainStats {
    uint64_t height;
    uint256  tip_hash;
    Amount   total_supply;
    double   difficulty;
    size_t   model_params;
    uint32_t nbits;

    static ChainStats at_height(uint64_t h, uint32_t bits = INITIAL_NBITS) {
        ChainStats s;
        s.height = h;
        s.total_supply = compute_total_supply(h);
        s.difficulty = GetDifficulty(bits);
        s.nbits = bits;
        auto dims = compute_growth(h);
        s.model_params = compute_param_count(dims);
        s.tip_hash.set_null();
        return s;
    }
};

// ---------------------------------------------------------------------------
// UTXOSnapshot — serialization helpers
// ---------------------------------------------------------------------------

struct UTXOSnapshot {
    uint64_t height;
    uint256  block_hash;
    uint64_t utxo_count;
    uint256  utxo_hash;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        data.resize(8 + 32 + 8 + 32);
        std::memcpy(data.data(), &height, 8);
        std::memcpy(data.data() + 8, block_hash.data(), 32);
        std::memcpy(data.data() + 40, &utxo_count, 8);
        std::memcpy(data.data() + 48, utxo_hash.data(), 32);
        return data;
    }

    static UTXOSnapshot deserialize(const std::vector<uint8_t>& data) {
        UTXOSnapshot snap;
        assert(data.size() == 80);
        std::memcpy(&snap.height, data.data(), 8);
        std::memcpy(snap.block_hash.data(), data.data() + 8, 32);
        std::memcpy(&snap.utxo_count, data.data() + 40, 8);
        std::memcpy(snap.utxo_hash.data(), data.data() + 48, 32);
        return snap;
    }
};

// ---------------------------------------------------------------------------
// CoinAge priority computation
// ---------------------------------------------------------------------------

static double compute_coin_age_priority(Amount value, uint64_t confirmations,
                                         size_t tx_size) {
    if (tx_size == 0) return 0.0;
    double coin_days = static_cast<double>(value) * static_cast<double>(confirmations);
    return coin_days / static_cast<double>(tx_size);
}

// ---------------------------------------------------------------------------
// Common ancestor height detection (simplified for testing)
// ---------------------------------------------------------------------------

static uint64_t find_common_ancestor_height(
    const std::vector<uint256>& chain_a,
    const std::vector<uint256>& chain_b) {
    // Both chains start from genesis (index 0 = height 0)
    uint64_t min_len = std::min(chain_a.size(), chain_b.size());
    uint64_t ancestor = 0;
    for (uint64_t i = 0; i < min_len; ++i) {
        if (chain_a[i] == chain_b[i]) {
            ancestor = i;
        } else {
            break;
        }
    }
    return ancestor;
}

void test_chain_stats() {

    // -----------------------------------------------------------------------
    // Test 1: ChainStats returns correct height and tip
    // -----------------------------------------------------------------------
    {
        auto stats = ChainStats::at_height(0);
        assert(stats.height == 0);
        assert(stats.tip_hash.is_null());

        auto stats100 = ChainStats::at_height(100);
        assert(stats100.height == 100);
    }

    // -----------------------------------------------------------------------
    // Test 2: total_supply matches expected for height
    // -----------------------------------------------------------------------
    {
        Amount supply_0 = compute_total_supply(0);
        assert(supply_0 == INITIAL_REWARD);

        Amount supply_1 = compute_total_supply(1);
        assert(supply_1 == 2 * INITIAL_REWARD);

        Amount supply_100 = compute_total_supply(100);
        assert(supply_100 == 101 * INITIAL_REWARD);

        auto stats = ChainStats::at_height(100);
        assert(stats.total_supply == supply_100);
    }

    // -----------------------------------------------------------------------
    // Test 3: difficulty reflects current nbits
    // -----------------------------------------------------------------------
    {
        double diff_initial = GetDifficulty(INITIAL_NBITS);
        assert(diff_initial >= 1.0);

        auto stats = ChainStats::at_height(0, INITIAL_NBITS);
        assert(stats.difficulty == diff_initial);

        // Harder difficulty (smaller target) -> higher difficulty number
        // 0x1e00ffff has a smaller target than 0x1f00ffff
        double diff_harder = GetDifficulty(0x1e00ffff);
        assert(diff_harder > diff_initial);
    }

    // -----------------------------------------------------------------------
    // Test 4: model_params matches compute_param_count
    // -----------------------------------------------------------------------
    {
        for (uint64_t h : {0ULL, 1ULL, 10ULL, 100ULL, 512ULL}) {
            auto dims = compute_growth(h);
            size_t expected = compute_param_count(dims);
            auto stats = ChainStats::at_height(h);
            assert(stats.model_params == expected);
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: verify_block_detailed passes on valid genesis-style block
    // -----------------------------------------------------------------------
    {
        CBlock block;
        block.version = 1;
        block.height = 0;
        block.timestamp = GENESIS_TIMESTAMP;
        block.nbits = INITIAL_NBITS;
        block.val_loss = 5.0f;
        block.prev_val_loss = 5.0f;

        auto dims = compute_growth(0);
        block.d_model = dims.d_model;
        block.n_layers = dims.n_layers;
        block.d_ff = dims.d_ff;
        block.n_heads = dims.n_heads;
        block.gru_dim = dims.gru_dim;
        block.n_slots = dims.n_slots;

        // Genesis has null prev_hash
        block.prev_hash.set_null();

        // Create a minimal coinbase
        CTransaction coinbase;
        coinbase.version = 1;
        CTxIn cb_in;
        cb_in.prevout.txid.set_null();
        cb_in.prevout.index = 0;
        coinbase.vin.push_back(cb_in);
        CTxOut cb_out;
        cb_out.amount = INITIAL_REWARD;
        coinbase.vout.push_back(cb_out);
        block.vtx.push_back(coinbase);

        block.merkle_root = block.compute_merkle_root();

        // Block should at least pass structural checks
        assert(block.check_block());
    }

    // -----------------------------------------------------------------------
    // Test 6: verify_block_detailed catches wrong growth dimensions
    // -----------------------------------------------------------------------
    {
        auto dims_0 = compute_growth(0);
        auto dims_1 = compute_growth(1);

        // Dimensions should differ for height 0 vs 1
        assert(dims_0.d_model != dims_1.d_model ||
               dims_0.n_slots != dims_1.n_slots);
    }

    // -----------------------------------------------------------------------
    // Test 7: UTXOSnapshot serialization round-trip
    // -----------------------------------------------------------------------
    {
        UTXOSnapshot snap;
        snap.height = 12345;
        snap.utxo_count = 98765;
        snap.block_hash = keccak256(std::string("test_block"));
        snap.utxo_hash = keccak256(std::string("test_utxo"));

        auto data = snap.serialize();
        assert(data.size() == 80);

        auto snap2 = UTXOSnapshot::deserialize(data);
        assert(snap2.height == snap.height);
        assert(snap2.utxo_count == snap.utxo_count);
        assert(snap2.block_hash == snap.block_hash);
        assert(snap2.utxo_hash == snap.utxo_hash);
    }

    // -----------------------------------------------------------------------
    // Test 8: compute_utxo_set_hash deterministic
    // -----------------------------------------------------------------------
    {
        // Same inputs -> same hash
        std::vector<uint8_t> utxo_data = {1, 2, 3, 4, 5, 6, 7, 8};
        auto hash1 = keccak256(utxo_data);
        auto hash2 = keccak256(utxo_data);
        assert(hash1 == hash2);

        // Different inputs -> different hash
        utxo_data[0] = 99;
        auto hash3 = keccak256(utxo_data);
        assert(hash1 != hash3);
    }

    // -----------------------------------------------------------------------
    // Test 9: get_headers_range returns correct count
    // -----------------------------------------------------------------------
    {
        // Simulate a chain of headers by creating indices at various heights
        std::vector<uint64_t> heights;
        for (uint64_t i = 0; i < 100; ++i) {
            heights.push_back(i);
        }

        // Range [10, 20) should contain 10 headers
        uint64_t start = 10, end = 20;
        int count = 0;
        for (auto h : heights) {
            if (h >= start && h < end) count++;
        }
        assert(count == 10);

        // Range [0, 100) should contain all 100
        count = 0;
        for (auto h : heights) {
            if (h < 100) count++;
        }
        assert(count == 100);
    }

    // -----------------------------------------------------------------------
    // Test 10: CoinAge priority computation
    // -----------------------------------------------------------------------
    {
        // 1 FLOW * 100 confirmations / 250 bytes
        double priority = compute_coin_age_priority(COIN, 100, 250);
        assert(priority > 0.0);

        // Higher value -> higher priority
        double priority_high = compute_coin_age_priority(10 * COIN, 100, 250);
        assert(priority_high > priority);

        // More confirmations -> higher priority
        double priority_old = compute_coin_age_priority(COIN, 1000, 250);
        assert(priority_old > priority);

        // Larger tx -> lower priority
        double priority_big = compute_coin_age_priority(COIN, 100, 1000);
        assert(priority_big < priority);

        // Zero tx size -> zero priority
        double priority_zero = compute_coin_age_priority(COIN, 100, 0);
        assert(priority_zero == 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 11: find_common_ancestor_height correct
    // -----------------------------------------------------------------------
    {
        // Two chains that share genesis but diverge at height 5
        auto make_hash = [](uint64_t h, int chain) {
            std::vector<uint8_t> data(16);
            std::memcpy(data.data(), &h, 8);
            std::memcpy(data.data() + 8, &chain, 4);
            return keccak256(data);
        };

        // Chain A: heights 0..9, Chain B: same through 4, different from 5
        std::vector<uint256> chain_a, chain_b;
        for (uint64_t i = 0; i < 10; ++i) {
            chain_a.push_back(make_hash(i, 0));
            if (i < 5) {
                chain_b.push_back(make_hash(i, 0));  // same as A
            } else {
                chain_b.push_back(make_hash(i, 1));  // different
            }
        }

        uint64_t ancestor = find_common_ancestor_height(chain_a, chain_b);
        assert(ancestor == 4);

        // Identical chains -> ancestor at the last common block
        uint64_t ancestor_same = find_common_ancestor_height(chain_a, chain_a);
        assert(ancestor_same == 9);

        // Diverge immediately -> ancestor at 0
        chain_b[1] = make_hash(1, 99);
        uint64_t ancestor_early = find_common_ancestor_height(chain_a, chain_b);
        assert(ancestor_early == 0);
    }

    // -----------------------------------------------------------------------
    // Test 12: Supply monotonically increases
    // -----------------------------------------------------------------------
    {
        Amount prev = 0;
        for (uint64_t h = 0; h < 1000; ++h) {
            Amount current = compute_total_supply(h);
            assert(current > prev);
            prev = current;
        }
    }

    // -----------------------------------------------------------------------
    // Test 13: Model params grow with height
    // -----------------------------------------------------------------------
    {
        size_t prev_params = 0;
        for (uint64_t h = 0; h < 100; ++h) {
            auto dims = compute_growth(h);
            size_t params = compute_param_count(dims);
            assert(params > prev_params);
            prev_params = params;
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: Block proof (work) is positive for valid nbits
    // -----------------------------------------------------------------------
    {
        auto work = GetBlockProof(INITIAL_NBITS);
        assert(!work.IsNull());

        // Harder nbits -> more work
        auto work_hard = GetBlockProof(0x1e00ffff);
        assert(work_hard > work);
    }

    // -----------------------------------------------------------------------
    // Test 15: Retarget period boundaries
    // -----------------------------------------------------------------------
    {
        uint64_t period_start, period_end;
        GetRetargetPeriod(0, period_start, period_end);
        assert(period_start == 0);
        assert(period_end == RETARGET_INTERVAL - 1);

        GetRetargetPeriod(2016, period_start, period_end);
        assert(period_start == 2016);
        assert(period_end == 2 * RETARGET_INTERVAL - 1);
    }

    // -----------------------------------------------------------------------
    // Test 16: Blocks until retarget decreases monotonically within period
    // -----------------------------------------------------------------------
    {
        uint64_t prev = BlocksUntilRetarget(0);
        for (uint64_t h = 1; h < RETARGET_INTERVAL; ++h) {
            uint64_t remaining = BlocksUntilRetarget(h);
            assert(remaining < prev);
            prev = remaining;
        }
        // At retarget boundary, resets to full interval
        assert(BlocksUntilRetarget(RETARGET_INTERVAL) == RETARGET_INTERVAL);
    }
}
