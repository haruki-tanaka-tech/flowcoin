// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for mining session tracking: MiningStats accumulation,
// TrainingConfig learning rate schedules (warmup, cosine decay),
// RewardTracker recording and querying, total/average reward
// computation, and MiningStats formatting.

#include "mining/miner.h"
#include "consensus/params.h"
#include "util/types.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>

using namespace flow;
using namespace flow::consensus;

// ---- MiningSession tracker -------------------------------------------------

struct MiningSession {
    uint64_t blocks_mined = 0;
    uint64_t total_train_steps = 0;
    double total_train_time_s = 0.0;
    float best_val_loss = 100.0f;
    int64_t session_start = 0;
    int64_t last_block_time = 0;

    void record_block(uint32_t train_steps, double train_time, float val_loss, int64_t block_time) {
        blocks_mined++;
        total_train_steps += train_steps;
        total_train_time_s += train_time;
        if (val_loss < best_val_loss) best_val_loss = val_loss;
        last_block_time = block_time;
    }

    double avg_steps_per_block() const {
        return (blocks_mined > 0)
            ? static_cast<double>(total_train_steps) / blocks_mined
            : 0.0;
    }

    double avg_train_time() const {
        return (blocks_mined > 0) ? total_train_time_s / blocks_mined : 0.0;
    }

    std::string format_stats() const {
        std::string s = "Blocks: " + std::to_string(blocks_mined);
        s += " | Steps: " + std::to_string(total_train_steps);
        s += " | Best loss: " + std::to_string(best_val_loss);
        s += " | Avg time: " + std::to_string(avg_train_time()) + "s";
        return s;
    }
};

// ---- TrainingConfig with LR schedule ---------------------------------------

struct TrainingConfig {
    float initial_lr = 0.001f;
    float min_lr = 0.00001f;
    uint32_t warmup_steps = 100;
    uint32_t total_steps = 10000;

    float get_lr(uint32_t step) const {
        if (step < warmup_steps) {
            // Linear warmup from 0 to initial_lr
            return initial_lr * static_cast<float>(step) / static_cast<float>(warmup_steps);
        }

        // Cosine decay from initial_lr to min_lr
        uint32_t decay_steps = total_steps - warmup_steps;
        uint32_t decay_step = step - warmup_steps;
        if (decay_step >= decay_steps) return min_lr;

        float progress = static_cast<float>(decay_step) / static_cast<float>(decay_steps);
        float cosine_factor = 0.5f * (1.0f + std::cos(static_cast<float>(M_PI) * progress));
        return min_lr + (initial_lr - min_lr) * cosine_factor;
    }
};

// ---- RewardTracker ---------------------------------------------------------

class RewardTracker {
public:
    struct RewardEntry {
        Amount reward;
        int64_t timestamp;
        uint64_t height;
    };

    void record(Amount reward, int64_t timestamp, uint64_t height) {
        entries_.push_back({reward, timestamp, height});
        total_earned_ += reward;
    }

    Amount total_earned() const { return total_earned_; }

    double avg_reward_per_hour() const {
        if (entries_.size() < 2) return 0.0;
        int64_t span = entries_.back().timestamp - entries_.front().timestamp;
        if (span <= 0) return 0.0;
        double hours = static_cast<double>(span) / 3600.0;
        return static_cast<double>(total_earned_) / hours;
    }

    size_t count() const { return entries_.size(); }

    Amount reward_at(size_t idx) const {
        return entries_.at(idx).reward;
    }

    uint64_t height_at(size_t idx) const {
        return entries_.at(idx).height;
    }

private:
    std::vector<RewardEntry> entries_;
    Amount total_earned_ = 0;
};

void test_mining_session() {

    // -----------------------------------------------------------------------
    // Test 1: MiningSession statistics accumulate correctly
    // -----------------------------------------------------------------------
    {
        MiningSession session;
        session.session_start = GENESIS_TIMESTAMP;

        assert(session.blocks_mined == 0);
        assert(session.total_train_steps == 0);

        session.record_block(5000, 120.0, 4.5f, GENESIS_TIMESTAMP + 600);
        assert(session.blocks_mined == 1);
        assert(session.total_train_steps == 5000);
        assert(session.best_val_loss == 4.5f);

        session.record_block(6000, 150.0, 4.2f, GENESIS_TIMESTAMP + 1200);
        assert(session.blocks_mined == 2);
        assert(session.total_train_steps == 11000);
        assert(session.best_val_loss == 4.2f);

        session.record_block(4000, 100.0, 4.8f, GENESIS_TIMESTAMP + 1800);
        assert(session.blocks_mined == 3);
        assert(session.total_train_steps == 15000);
        assert(session.best_val_loss == 4.2f);  // unchanged (4.8 > 4.2)
    }

    // -----------------------------------------------------------------------
    // Test 2: MiningSession averages
    // -----------------------------------------------------------------------
    {
        MiningSession session;
        session.record_block(3000, 60.0, 5.0f, 1000);
        session.record_block(5000, 100.0, 4.0f, 2000);
        session.record_block(4000, 80.0, 3.0f, 3000);

        assert(std::abs(session.avg_steps_per_block() - 4000.0) < 0.01);
        assert(std::abs(session.avg_train_time() - 80.0) < 0.01);
    }

    // -----------------------------------------------------------------------
    // Test 3: TrainingConfig LR warmup — linear increase from 0 to initial_lr
    // -----------------------------------------------------------------------
    {
        TrainingConfig config;
        config.initial_lr = 0.001f;
        config.warmup_steps = 100;
        config.total_steps = 10000;

        // Step 0: lr = 0
        float lr0 = config.get_lr(0);
        assert(lr0 == 0.0f);

        // Step 50: lr = 0.001 * 50/100 = 0.0005
        float lr50 = config.get_lr(50);
        assert(std::abs(lr50 - 0.0005f) < 1e-6f);

        // Step 100: lr = initial_lr (end of warmup)
        float lr100 = config.get_lr(100);
        assert(std::abs(lr100 - 0.001f) < 1e-6f);

        // Linear increase during warmup
        float lr25 = config.get_lr(25);
        float lr75 = config.get_lr(75);
        assert(lr25 < lr50);
        assert(lr50 < lr75);
        assert(lr75 < lr100);
    }

    // -----------------------------------------------------------------------
    // Test 4: TrainingConfig cosine decay — decreases to min_lr
    // -----------------------------------------------------------------------
    {
        TrainingConfig config;
        config.initial_lr = 0.001f;
        config.min_lr = 0.00001f;
        config.warmup_steps = 100;
        config.total_steps = 10000;

        // Just after warmup: should be close to initial_lr
        float lr_start = config.get_lr(101);
        assert(lr_start > 0.0009f);

        // At midpoint of decay: should be roughly (initial + min) / 2
        uint32_t mid = 100 + (10000 - 100) / 2;
        float lr_mid = config.get_lr(mid);
        float expected_mid = 0.5f * (0.001f + 0.00001f);
        assert(std::abs(lr_mid - expected_mid) < 0.0002f);

        // At end: should be close to min_lr
        float lr_end = config.get_lr(9999);
        assert(lr_end < 0.0001f);

        // After total_steps: exactly min_lr
        float lr_past = config.get_lr(10000);
        assert(lr_past == config.min_lr);
    }

    // -----------------------------------------------------------------------
    // Test 5: TrainingConfig correct at step=0, middle, end
    // -----------------------------------------------------------------------
    {
        TrainingConfig config;
        config.initial_lr = 0.01f;
        config.min_lr = 0.0001f;
        config.warmup_steps = 0;  // no warmup
        config.total_steps = 1000;

        // Step 0: initial_lr (no warmup)
        float lr0 = config.get_lr(0);
        assert(std::abs(lr0 - 0.01f) < 1e-6f);

        // Step 500: midpoint of cosine
        float lr500 = config.get_lr(500);
        float expected = 0.5f * (0.01f + 0.0001f);
        assert(std::abs(lr500 - expected) < 0.001f);

        // Step 1000: min_lr
        float lr1000 = config.get_lr(1000);
        assert(lr1000 == 0.0001f);
    }

    // -----------------------------------------------------------------------
    // Test 6: RewardTracker record and query
    // -----------------------------------------------------------------------
    {
        RewardTracker tracker;

        tracker.record(50 * COIN, GENESIS_TIMESTAMP, 0);
        tracker.record(50 * COIN, GENESIS_TIMESTAMP + 600, 1);
        tracker.record(50 * COIN, GENESIS_TIMESTAMP + 1200, 2);

        assert(tracker.count() == 3);
        assert(tracker.reward_at(0) == 50 * COIN);
        assert(tracker.reward_at(1) == 50 * COIN);
        assert(tracker.reward_at(2) == 50 * COIN);
        assert(tracker.height_at(0) == 0);
        assert(tracker.height_at(1) == 1);
        assert(tracker.height_at(2) == 2);
    }

    // -----------------------------------------------------------------------
    // Test 7: RewardTracker total_earned sums correctly
    // -----------------------------------------------------------------------
    {
        RewardTracker tracker;

        tracker.record(50 * COIN, 1000, 0);
        assert(tracker.total_earned() == 50 * COIN);

        tracker.record(50 * COIN, 1600, 1);
        assert(tracker.total_earned() == 100 * COIN);

        tracker.record(25 * COIN, 2200, 210000);
        assert(tracker.total_earned() == 100 * COIN + 25 * COIN);
    }

    // -----------------------------------------------------------------------
    // Test 8: RewardTracker avg_reward_per_hour computed
    // -----------------------------------------------------------------------
    {
        RewardTracker tracker;

        // 6 blocks in 1 hour (3600 seconds)
        for (int i = 0; i < 6; i++) {
            tracker.record(50 * COIN, GENESIS_TIMESTAMP + i * 600, i);
        }

        // Total: 300 FLOW over 3000 seconds = 0.833 hours
        // avg_per_hour = 300 * COIN / 0.833
        double avg = tracker.avg_reward_per_hour();
        assert(avg > 0.0);

        // Approximate: 300 FLOW / (3000/3600 hours) = 360 FLOW/hour
        double expected = static_cast<double>(300 * COIN) / (3000.0 / 3600.0);
        assert(std::abs(avg - expected) < 1.0);
    }

    // -----------------------------------------------------------------------
    // Test 9: RewardTracker with single entry returns 0 avg
    // -----------------------------------------------------------------------
    {
        RewardTracker tracker;
        tracker.record(50 * COIN, 1000, 0);
        assert(tracker.avg_reward_per_hour() == 0.0);
    }

    // -----------------------------------------------------------------------
    // Test 10: MiningSession format_stats produces readable string
    // -----------------------------------------------------------------------
    {
        MiningSession session;
        session.record_block(5000, 120.0, 4.5f, 1000);
        session.record_block(6000, 130.0, 4.2f, 1600);

        std::string stats = session.format_stats();
        assert(!stats.empty());
        assert(stats.find("Blocks: 2") != std::string::npos);
        assert(stats.find("Steps: 11000") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 11: MiningStats from miner.h
    // -----------------------------------------------------------------------
    {
        MiningStats stats;
        assert(stats.blocks_mined == 0);
        assert(stats.blocks_submitted == 0);
        assert(stats.blocks_accepted == 0);
        assert(stats.blocks_rejected == 0);
        assert(stats.total_train_steps == 0);
        assert(stats.total_nonces_tried == 0);
        assert(stats.best_val_loss == 100.0f);

        stats.blocks_mined = 10;
        stats.blocks_submitted = 10;
        stats.blocks_accepted = 8;
        stats.blocks_rejected = 2;
        stats.total_train_steps = 50000;

        assert(stats.blocks_accepted + stats.blocks_rejected == stats.blocks_submitted);

        std::string s = stats.to_string();
        assert(!s.empty());
    }

    // -----------------------------------------------------------------------
    // Test 12: TrainingConfig monotonic decay after warmup
    // -----------------------------------------------------------------------
    {
        TrainingConfig config;
        config.initial_lr = 0.001f;
        config.min_lr = 0.00001f;
        config.warmup_steps = 50;
        config.total_steps = 5000;

        float prev_lr = config.get_lr(50);
        for (uint32_t step = 100; step <= 5000; step += 100) {
            float lr = config.get_lr(step);
            assert(lr <= prev_lr);
            prev_lr = lr;
        }
    }

    // -----------------------------------------------------------------------
    // Test 13: Warmup is strictly monotonic
    // -----------------------------------------------------------------------
    {
        TrainingConfig config;
        config.initial_lr = 0.01f;
        config.warmup_steps = 200;

        float prev = 0.0f;
        for (uint32_t step = 0; step <= 200; step += 10) {
            float lr = config.get_lr(step);
            assert(lr >= prev);
            prev = lr;
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: MiningConfig defaults are reasonable
    // -----------------------------------------------------------------------
    {
        MinerConfig config;
        assert(config.learning_rate > 0.0f);
        assert(config.learning_rate < 1.0f);
        assert(config.weight_decay > 0.0f);
        assert(config.sparse_threshold > 0.0f);
        assert(config.max_train_steps > 0);
        assert(config.batch_size >= MIN_BATCH_SIZE);
        assert(config.batch_size <= MAX_BATCH_SIZE);
    }

    // -----------------------------------------------------------------------
    // Test 15: format_hashrate produces readable output
    // -----------------------------------------------------------------------
    {
        std::string h1 = format_hashrate(1000.0);
        assert(!h1.empty());

        std::string h2 = format_hashrate(1000000.0);
        assert(!h2.empty());

        std::string h3 = format_hashrate(0.0);
        assert(!h3.empty());
    }
}
