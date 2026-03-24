// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for the FeeEstimator: fee rate estimation from confirmation history.

#include "wallet/fees.h"
#include "util/types.h"
#include <cassert>
#include <cstdint>

void test_fee_estimator() {
    using namespace flow;

    // Test 1: Estimate with no history returns minimum
    {
        FeeEstimator estimator;
        assert(estimator.history_size() == 0);

        Amount rate = estimator.estimate_fee_rate(6);
        assert(rate == FeeEstimator::MIN_RELAY_FEE_RATE);
    }

    // Test 2: Record confirmations, estimate reflects them
    {
        FeeEstimator estimator;

        // Record several transactions with different fee rates
        // tx_size=200 bytes, fee=1000 atomic units -> rate=5 per byte
        estimator.record_confirmation(200, 1000, 1);
        // tx_size=200 bytes, fee=2000 -> rate=10 per byte
        estimator.record_confirmation(200, 2000, 1);
        // tx_size=200 bytes, fee=1400 -> rate=7 per byte
        estimator.record_confirmation(200, 1400, 1);

        assert(estimator.history_size() == 3);

        // Estimate for target=1 should reflect recorded rates
        Amount rate = estimator.estimate_fee_rate(1);
        // Should be >= minimum
        assert(rate >= FeeEstimator::MIN_RELAY_FEE_RATE);
        // With rates 5, 10, 7, median is 7
        // Allow some tolerance for implementation details
        assert(rate >= 5);
        assert(rate <= 15);
    }

    // Test 3: calculate_fee returns reasonable values
    {
        FeeEstimator estimator;

        // With no history, should use minimum rate
        Amount fee = estimator.calculate_fee(250, 6);
        // MIN_RELAY_FEE_RATE (1) * 250 bytes = 250
        assert(fee == 250);

        // After recording some data
        estimator.record_confirmation(100, 500, 2);  // rate=5
        estimator.record_confirmation(100, 800, 3);  // rate=8
        estimator.record_confirmation(100, 600, 1);  // rate=6

        fee = estimator.calculate_fee(100, 6);
        assert(fee > 0);
        assert(fee <= 1000);  // Sanity: not absurdly high
    }

    // Test 4: Fee rate scales with confirmation depth target
    {
        FeeEstimator estimator;

        // Fast confirmation transactions (1 block) with high fee rates
        for (int i = 0; i < 20; i++) {
            estimator.record_confirmation(200, 4000, 1);  // rate=20
        }
        // Slow confirmation transactions (10 blocks) with low fee rates
        for (int i = 0; i < 20; i++) {
            estimator.record_confirmation(200, 400, 10);  // rate=2
        }

        Amount rate_fast = estimator.estimate_fee_rate(1);
        Amount rate_slow = estimator.estimate_fee_rate(10);

        // Fast confirmation should require higher fee rate
        assert(rate_fast >= rate_slow);
    }

    // Test 5: Clear removes all history
    {
        FeeEstimator estimator;
        estimator.record_confirmation(100, 500, 1);
        estimator.record_confirmation(100, 600, 2);
        assert(estimator.history_size() == 2);

        estimator.clear();
        assert(estimator.history_size() == 0);

        // After clearing, should return minimum
        Amount rate = estimator.estimate_fee_rate(6);
        assert(rate == FeeEstimator::MIN_RELAY_FEE_RATE);
    }

    // Test 6: Zero-size transaction is ignored
    {
        FeeEstimator estimator;
        estimator.record_confirmation(0, 1000, 1);
        assert(estimator.history_size() == 0);
    }

    // Test 7: Large number of records doesn't exceed capacity
    {
        FeeEstimator estimator;
        for (int i = 0; i < 20000; i++) {
            estimator.record_confirmation(200, 1000 + i, 1);
        }
        // Should be capped at MAX_HISTORY (10000)
        assert(estimator.history_size() <= 10000);

        // Should still produce valid estimates
        Amount rate = estimator.estimate_fee_rate(6);
        assert(rate >= FeeEstimator::MIN_RELAY_FEE_RATE);
    }

    // Test 8: calculate_fee for zero-size tx
    {
        FeeEstimator estimator;
        Amount fee = estimator.calculate_fee(0, 6);
        assert(fee == 0);
    }
}
