// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for Proof-of-Training verification (consensus/pow.h).

#include "consensus/pow.h"
#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "primitives/block.h"
#include "util/arith_uint256.h"
#include "util/types.h"

#include <cassert>
#include <cmath>
#include <cstring>

using namespace flow;
using namespace flow::consensus;

// Helper: create a block header with a specific hash that meets the target
static CBlockHeader make_valid_header() {
    auto kp = generate_keypair();
    auto dims = compute_growth(0, 0);

    CBlockHeader hdr;
    hdr.height = 0;
    hdr.timestamp = GENESIS_TIMESTAMP;
    hdr.nbits = INITIAL_NBITS;
    hdr.val_loss = 5.0f;
    hdr.prev_val_loss = 0.0f;
    hdr.d_model = dims.d_model;
    hdr.n_layers = dims.n_layers;
    hdr.d_ff = dims.d_ff;
    hdr.n_heads = dims.n_heads;
    hdr.gru_dim = dims.gru_dim;
    hdr.n_slots = dims.n_slots;
    hdr.train_steps = 5000;
    hdr.version = 1;
    hdr.stagnation = 0;
    hdr.nonce = 0;

    std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);

    auto unsigned_data = hdr.get_unsigned_data();
    auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                            kp.privkey.data(), kp.pubkey.data());
    std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

    return hdr;
}

void test_pow() {
    // -----------------------------------------------------------------------
    // Test 1: GetPowLimit returns a large, non-zero target
    // -----------------------------------------------------------------------
    {
        arith_uint256 limit = GetPowLimit();
        assert(!limit.IsZero());
        assert(!limit.IsNull());
    }

    // -----------------------------------------------------------------------
    // Test 2: GetDifficulty returns 1.0 for initial nbits
    // -----------------------------------------------------------------------
    {
        double diff = GetDifficulty(INITIAL_NBITS);
        assert(diff >= 0.99 && diff <= 1.01);
    }

    // -----------------------------------------------------------------------
    // Test 3: GetDifficulty returns 0.0 for invalid nbits
    // -----------------------------------------------------------------------
    {
        double diff = GetDifficulty(0);
        assert(diff == 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 4: GetDifficulty increases when target decreases
    // -----------------------------------------------------------------------
    {
        // Create a harder target (smaller nbits exponent or mantissa)
        // Bitcoin's 0x1d00ffff is harder than FlowCoin's 0x1f00ffff
        double easy_diff = GetDifficulty(INITIAL_NBITS);
        double hard_diff = GetDifficulty(0x1d00ffff);
        assert(hard_diff > easy_diff);
    }

    // -----------------------------------------------------------------------
    // Test 5: CheckProofOfTraining with valid header at easy difficulty
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_header();
        // At initial difficulty (very easy target), most hashes will pass
        // We try multiple nonces to find one that works
        bool found = false;
        for (uint32_t nonce = 0; nonce < 10000; nonce++) {
            hdr.nonce = nonce;
            if (CheckProofOfTraining(hdr)) {
                found = true;
                break;
            }
        }
        // With ~2^226 target, essentially every hash should pass
        assert(found);
    }

    // -----------------------------------------------------------------------
    // Test 6: CheckProofOfTraining with extremely hard target
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_header();
        // Set an extremely hard target (exponent 1, mantissa 1)
        // Target = 0x01 << (8 * (1 - 3)) which is invalid (negative shift)
        // Use a very small valid target instead: 0x0300ffff -> target = 0x00ffff
        hdr.nbits = 0x0300ffff;
        // This target is so small that a random hash is astronomically
        // unlikely to be below it. Verify the check fails.
        bool passed = CheckProofOfTraining(hdr);
        // It is expected to fail with such a tiny target
        assert(!passed);
    }

    // -----------------------------------------------------------------------
    // Test 7: GetBlockProof returns non-zero for valid nbits
    // -----------------------------------------------------------------------
    {
        arith_uint256 proof = GetBlockProof(INITIAL_NBITS);
        assert(!proof.IsZero());
    }

    // -----------------------------------------------------------------------
    // Test 8: GetBlockProof increases with harder difficulty
    // -----------------------------------------------------------------------
    {
        arith_uint256 easy_proof = GetBlockProof(INITIAL_NBITS);
        arith_uint256 hard_proof = GetBlockProof(0x1d00ffff);
        // Harder difficulty (smaller target) means more expected work
        assert(hard_proof > easy_proof);
    }

    // -----------------------------------------------------------------------
    // Test 9: GetBlockProof returns zero for invalid nbits
    // -----------------------------------------------------------------------
    {
        arith_uint256 proof = GetBlockProof(0);
        assert(proof.IsZero());
    }

    // -----------------------------------------------------------------------
    // Test 10: EstimateNetworkHashrate with known difficulty
    // -----------------------------------------------------------------------
    {
        double hashrate = EstimateNetworkHashrate(1.0);
        // hashrate = 1.0 * 2^32 / 600 = ~7,158,278
        double expected = 4294967296.0 / 600.0;
        assert(std::abs(hashrate - expected) < 1.0);
    }

    // -----------------------------------------------------------------------
    // Test 11: EstimateNetworkHashrate returns 0 for non-positive difficulty
    // -----------------------------------------------------------------------
    {
        assert(EstimateNetworkHashrate(0.0) == 0.0);
        assert(EstimateNetworkHashrate(-1.0) == 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 12: DifficultyToTarget round-trip
    // -----------------------------------------------------------------------
    {
        // Difficulty 1.0 should map back to INITIAL_NBITS
        uint32_t nbits = DifficultyToTarget(1.0);
        double diff = GetDifficulty(nbits);
        assert(std::abs(diff - 1.0) < 0.1);
    }

    // -----------------------------------------------------------------------
    // Test 13: DifficultyToTarget with higher difficulty
    // -----------------------------------------------------------------------
    {
        double target_diff = 100.0;
        uint32_t nbits = DifficultyToTarget(target_diff);
        double recovered = GetDifficulty(nbits);
        // Should be roughly the same (some precision loss is expected)
        assert(recovered > target_diff * 0.5);
        assert(recovered < target_diff * 2.0);
    }

    // -----------------------------------------------------------------------
    // Test 14: DifficultyToTarget returns INITIAL_NBITS for invalid input
    // -----------------------------------------------------------------------
    {
        assert(DifficultyToTarget(0.0) == INITIAL_NBITS);
        assert(DifficultyToTarget(-1.0) == INITIAL_NBITS);
    }

    // -----------------------------------------------------------------------
    // Test 15: AllowMinDifficultyBlocks
    // -----------------------------------------------------------------------
    {
        assert(AllowMinDifficultyBlocks(true) == true);
        assert(AllowMinDifficultyBlocks(false) == false);
    }

    // -----------------------------------------------------------------------
    // Test 16: GetNextWorkRequired in regtest always returns initial
    // -----------------------------------------------------------------------
    {
        uint32_t next = GetNextWorkRequired(2015, INITIAL_NBITS, 0, 100, true);
        assert(next == INITIAL_NBITS);
    }

    // -----------------------------------------------------------------------
    // Test 17: IsRetargetHeight
    // -----------------------------------------------------------------------
    {
        assert(!IsRetargetHeight(0));
        assert(!IsRetargetHeight(1));
        assert(!IsRetargetHeight(2015));
        assert(IsRetargetHeight(2016));
        assert(!IsRetargetHeight(2017));
        assert(IsRetargetHeight(4032));
    }

    // -----------------------------------------------------------------------
    // Test 18: BlocksUntilRetarget
    // -----------------------------------------------------------------------
    {
        assert(BlocksUntilRetarget(0) == RETARGET_INTERVAL);
        assert(BlocksUntilRetarget(1) == RETARGET_INTERVAL - 1);
        assert(BlocksUntilRetarget(2015) == 1);
        assert(BlocksUntilRetarget(2016) == RETARGET_INTERVAL);
    }

    // -----------------------------------------------------------------------
    // Test 19: GetRetargetPeriod
    // -----------------------------------------------------------------------
    {
        uint64_t start, end;
        GetRetargetPeriod(0, start, end);
        assert(start == 0);
        assert(end == 2015);

        GetRetargetPeriod(2016, start, end);
        assert(start == 2016);
        assert(end == 4031);

        GetRetargetPeriod(100, start, end);
        assert(start == 0);
        assert(end == 2015);
    }

    // -----------------------------------------------------------------------
    // Test 20: EstimateTimeToBlock
    // -----------------------------------------------------------------------
    {
        double time = EstimateTimeToBlock(1.0, 4294967296.0 / 600.0);
        // With hashrate that finds one block per 600s at diff 1:
        assert(std::abs(time - 600.0) < 1.0);
    }

    // -----------------------------------------------------------------------
    // Test 21: EstimateTimeToBlock with zero hashrate returns infinity
    // -----------------------------------------------------------------------
    {
        double time = EstimateTimeToBlock(1.0, 0.0);
        assert(std::isinf(time));
    }

    // -----------------------------------------------------------------------
    // Test 22: FormatTarget returns valid hex for initial nbits
    // -----------------------------------------------------------------------
    {
        std::string hex = FormatTarget(INITIAL_NBITS);
        assert(hex != "invalid");
        assert(!hex.empty());
    }

    // -----------------------------------------------------------------------
    // Test 23: FormatTarget returns "invalid" for nbits=0
    // -----------------------------------------------------------------------
    {
        std::string hex = FormatTarget(0);
        assert(hex == "invalid");
    }

    // -----------------------------------------------------------------------
    // Test 24: GetDifficultyProgress at genesis
    // -----------------------------------------------------------------------
    {
        int64_t now = GENESIS_TIMESTAMP + TARGET_BLOCK_TIME * 10;
        DifficultyProgress prog = GetDifficultyProgress(
            10, INITIAL_NBITS, GENESIS_TIMESTAMP, now);

        assert(prog.current_difficulty >= 0.99);
        assert(prog.current_difficulty <= 1.01);
        assert(prog.blocks_in_period == 10.0);
        assert(prog.blocks_until_retarget == RETARGET_INTERVAL - 10);
        assert(prog.estimated_hashrate > 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 25: GetDifficultyProgress period progress
    // -----------------------------------------------------------------------
    {
        int64_t now = GENESIS_TIMESTAMP + TARGET_BLOCK_TIME * 1008;
        DifficultyProgress prog = GetDifficultyProgress(
            1008, INITIAL_NBITS, GENESIS_TIMESTAMP, now);

        // 1008/2016 = 50%
        assert(prog.period_progress_pct > 49.0);
        assert(prog.period_progress_pct < 51.0);
    }

    // -----------------------------------------------------------------------
    // Test 26: GetDifficultyProgress estimated adjustment
    // -----------------------------------------------------------------------
    {
        // Blocks coming at exactly target rate: adjustment should be ~1.0
        int64_t period_start = GENESIS_TIMESTAMP;
        int64_t now = period_start + TARGET_BLOCK_TIME * 100;
        DifficultyProgress prog = GetDifficultyProgress(
            100, INITIAL_NBITS, period_start, now);

        assert(prog.estimated_adjustment > 0.8);
        assert(prog.estimated_adjustment < 1.2);
    }

    // -----------------------------------------------------------------------
    // Test 27: VerifyFullProofOfTraining basic validation
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_header();
        // With easy difficulty, try to find a valid block
        bool verified = false;
        for (uint32_t nonce = 0; nonce < 10000; nonce++) {
            hdr.nonce = nonce;
            // Re-sign after changing nonce
            auto kp = generate_keypair();
            std::memcpy(hdr.miner_pubkey.data(), kp.pubkey.data(), 32);
            auto unsigned_data = hdr.get_unsigned_data();
            auto sig = ed25519_sign(unsigned_data.data(), unsigned_data.size(),
                                    kp.privkey.data(), kp.pubkey.data());
            std::memcpy(hdr.miner_sig.data(), sig.data(), 64);

            if (VerifyFullProofOfTraining(hdr, INITIAL_NBITS, 0)) {
                verified = true;
                break;
            }
        }
        assert(verified);
    }

    // -----------------------------------------------------------------------
    // Test 28: VerifyFullProofOfTraining rejects wrong height
    // -----------------------------------------------------------------------
    {
        CBlockHeader hdr = make_valid_header();
        // Header says height 0, but we claim child_height 5
        // Should fail because header.height != child_height
        bool valid = VerifyFullProofOfTraining(hdr, INITIAL_NBITS, 5);
        assert(!valid);
    }

    // -----------------------------------------------------------------------
    // Test 29: GetNextWorkRequired non-retarget returns parent
    // -----------------------------------------------------------------------
    {
        for (uint64_t h = 1; h < RETARGET_INTERVAL; h += 100) {
            uint32_t next = GetNextWorkRequired(h - 1, INITIAL_NBITS,
                                                 0, 0, false);
            assert(next == INITIAL_NBITS);
        }
    }

    // -----------------------------------------------------------------------
    // Test 30: GetNextWorkRequired at retarget with double time
    // -----------------------------------------------------------------------
    {
        int64_t first = 0;
        int64_t last = RETARGET_TIMESPAN * 2;  // blocks took 2x longer
        uint32_t next = GetNextWorkRequired(
            RETARGET_INTERVAL - 1, INITIAL_NBITS, first, last, false);
        // Target should increase (easier) but clamped to powLimit
        assert(next == INITIAL_NBITS);  // already at powLimit
    }

    // -----------------------------------------------------------------------
    // Test 31: DifficultyToTarget at various values
    // -----------------------------------------------------------------------
    {
        double diffs[] = {1.0, 2.0, 10.0, 100.0, 1000.0};
        for (double d : diffs) {
            uint32_t nbits = DifficultyToTarget(d);
            assert(nbits != 0);
            double recovered = GetDifficulty(nbits);
            // Allow 50% tolerance due to compact representation
            assert(recovered > d * 0.5);
            assert(recovered < d * 2.0);
        }
    }

    // -----------------------------------------------------------------------
    // Test 32: Difficulty increases monotonically with smaller targets
    // -----------------------------------------------------------------------
    {
        uint32_t nbits_values[] = {
            0x1f00ffff,  // FlowCoin initial (easiest)
            0x1e00ffff,
            0x1d00ffff,  // Bitcoin initial
            0x1c00ffff,
            0x1b00ffff,
        };

        double prev_diff = 0.0;
        for (uint32_t nb : nbits_values) {
            double diff = GetDifficulty(nb);
            if (diff > 0.0) {
                assert(diff > prev_diff);
                prev_diff = diff;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 33: BlockProof increases monotonically with harder targets
    // -----------------------------------------------------------------------
    {
        arith_uint256 prev_proof(0);
        uint32_t nbits_values[] = {
            0x1f00ffff,
            0x1e00ffff,
            0x1d00ffff,
        };

        for (uint32_t nb : nbits_values) {
            arith_uint256 proof = GetBlockProof(nb);
            if (!proof.IsZero()) {
                assert(proof > prev_proof);
                prev_proof = proof;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 34: EstimateNetworkHashrate scales linearly with difficulty
    // -----------------------------------------------------------------------
    {
        double hr1 = EstimateNetworkHashrate(1.0);
        double hr10 = EstimateNetworkHashrate(10.0);
        double hr100 = EstimateNetworkHashrate(100.0);

        assert(std::abs(hr10 / hr1 - 10.0) < 0.001);
        assert(std::abs(hr100 / hr1 - 100.0) < 0.001);
    }

    // -----------------------------------------------------------------------
    // Test 35: validate_nbits rejects invalid values
    // -----------------------------------------------------------------------
    {
        assert(!validate_nbits(0));  // zero target
    }

    // -----------------------------------------------------------------------
    // Test 36: compare_difficulty
    // -----------------------------------------------------------------------
    {
        // Same difficulty
        assert(compare_difficulty(INITIAL_NBITS, INITIAL_NBITS) == 0);

        // 0x1e00ffff is harder than 0x1f00ffff (smaller target)
        int cmp = compare_difficulty(0x1e00ffff, 0x1f00ffff);
        assert(cmp == -1);  // a is harder

        cmp = compare_difficulty(0x1f00ffff, 0x1e00ffff);
        assert(cmp == 1);   // b is harder
    }

    // -----------------------------------------------------------------------
    // Test 37: compute_timespan_ratio
    // -----------------------------------------------------------------------
    {
        // Exact target time: ratio = 1.0
        double ratio = compute_timespan_ratio(0, RETARGET_TIMESPAN);
        assert(std::abs(ratio - 1.0) < 0.01);

        // 2x too fast: ratio < 1.0
        double fast = compute_timespan_ratio(0, RETARGET_TIMESPAN / 2);
        assert(fast < 1.0);

        // 2x too slow: ratio > 1.0
        double slow = compute_timespan_ratio(0, RETARGET_TIMESPAN * 2);
        assert(slow > 1.0);
    }
}
