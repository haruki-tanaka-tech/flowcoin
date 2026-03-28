// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Lightweight benchmark framework for FlowCoin.
// No external dependencies. Provides registration, timing, and reporting
// for micro-benchmarks of core subsystems.

#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

namespace flow {
namespace bench {

// ============================================================================
// Benchmark result
// ============================================================================

struct BenchResult {
    std::string name;
    int64_t iterations = 0;
    double total_ns = 0.0;
    double avg_ns = 0.0;
    double min_ns = 0.0;
    double max_ns = 0.0;
    double median_ns = 0.0;
    double stddev_ns = 0.0;
    double throughput = 0.0;
    size_t bytes_processed = 0;
    double bandwidth_mbps = 0.0;

    void print() const;
    static void print_header();
};

// ============================================================================
// Benchmark state (passed to benchmark functions)
// ============================================================================

class BenchState {
public:
    explicit BenchState(int64_t min_duration_ns = 1'000'000'000LL);

    bool keep_running();
    void pause_timing();
    void resume_timing();
    void set_bytes_per_iteration(size_t bytes);
    void set_name(const std::string& name);
    BenchResult get_result() const;
    int64_t iterations() const { return iterations_; }

private:
    std::string name_;
    int64_t min_duration_ns_;
    int64_t iterations_ = 0;
    int64_t max_iterations_ = 1;
    size_t bytes_per_iter_ = 0;
    bool running_ = false;

    std::chrono::high_resolution_clock::time_point start_time_;
    std::chrono::high_resolution_clock::time_point iter_start_;
    double total_ns_ = 0.0;
    std::vector<double> iter_times_;

    bool calibrated_ = false;
    int64_t calibration_iters_ = 0;
    double calibration_ns_ = 0.0;
};

// ============================================================================
// Benchmark registry
// ============================================================================

using BenchFn = std::function<void(BenchState&)>;

struct BenchEntry {
    std::string name;
    std::string group;
    BenchFn fn;
    int priority = 0;
};

class BenchRunner {
public:
    static BenchRunner& instance();

    void add(const std::string& name, const std::string& group,
             BenchFn fn, int priority = 0);

    void run_all();
    void run_filter(const std::string& filter);
    BenchResult run_single(const std::string& name);
    std::vector<std::string> list() const;

    void set_min_duration(int64_t ns) { min_duration_ns_ = ns; }
    void set_output_format(const std::string& format) { format_ = format; }

private:
    BenchRunner() = default;
    std::vector<BenchEntry> entries_;
    int64_t min_duration_ns_ = 1'000'000'000LL;
    std::string format_ = "console";

    BenchResult run_entry(const BenchEntry& entry);
    void print_csv(const std::vector<BenchResult>& results) const;
    void print_json(const std::vector<BenchResult>& results) const;
};

// ============================================================================
// Registration macro
// ============================================================================

#define BENCH(name) \
    static void bench_##name##_body(int _iterations); \
    static void bench_##name##_wrap(::flow::bench::BenchState& state) { \
        (void)state; \
        bench_##name##_body(1000); \
    } \
    static struct BenchReg_##name { \
        BenchReg_##name() { \
            ::flow::bench::BenchRunner::instance().add( \
                #name, "default", bench_##name##_wrap); \
        } \
    } bench_reg_##name; \
    static void bench_##name##_body(int _iterations)

} // namespace bench
} // namespace flow
