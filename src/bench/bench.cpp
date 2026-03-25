// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "bench.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <numeric>

namespace flow {
namespace bench {

// ============================================================================
// BenchResult
// ============================================================================

void BenchResult::print_header() {
    std::printf("%-40s %12s %12s %12s %12s %12s\n",
                "Benchmark", "Iterations", "Avg (ns)", "Min (ns)",
                "Max (ns)", "Throughput");
    std::printf("%s\n", std::string(112, '-').c_str());
}

void BenchResult::print() const {
    char throughput_str[32];
    if (bandwidth_mbps > 0.0) {
        std::snprintf(throughput_str, sizeof(throughput_str),
                      "%.1f MB/s", bandwidth_mbps);
    } else if (throughput > 0.0) {
        if (throughput >= 1e6) {
            std::snprintf(throughput_str, sizeof(throughput_str),
                          "%.1f Mops/s", throughput / 1e6);
        } else if (throughput >= 1e3) {
            std::snprintf(throughput_str, sizeof(throughput_str),
                          "%.1f Kops/s", throughput / 1e3);
        } else {
            std::snprintf(throughput_str, sizeof(throughput_str),
                          "%.1f ops/s", throughput);
        }
    } else {
        std::snprintf(throughput_str, sizeof(throughput_str), "N/A");
    }

    std::printf("%-40s %12lld %12.1f %12.1f %12.1f %12s\n",
                name.c_str(),
                static_cast<long long>(iterations),
                avg_ns, min_ns, max_ns,
                throughput_str);
}

// ============================================================================
// BenchState
// ============================================================================

BenchState::BenchState(int64_t min_duration_ns)
    : min_duration_ns_(min_duration_ns) {
}

bool BenchState::keep_running() {
    if (!calibrated_) {
        // First call: start calibration
        if (calibration_iters_ == 0) {
            start_time_ = std::chrono::high_resolution_clock::now();
            iter_start_ = start_time_;
            calibration_iters_ = 1;
            running_ = true;
            return true;
        }

        // Check if calibration is done
        auto now = std::chrono::high_resolution_clock::now();
        double elapsed = std::chrono::duration<double, std::nano>(
            now - start_time_).count();

        if (elapsed < 100'000'000.0 && calibration_iters_ < 1'000'000) {
            // Need more calibration iterations
            calibration_iters_ *= 2;
            start_time_ = std::chrono::high_resolution_clock::now();
            iter_start_ = start_time_;
            iterations_ = 0;
            iter_times_.clear();
            return true;
        }

        // Calibration complete -- estimate iterations needed
        calibration_ns_ = elapsed;
        double ns_per_iter = elapsed / static_cast<double>(calibration_iters_);
        if (ns_per_iter > 0.0) {
            max_iterations_ = static_cast<int64_t>(
                static_cast<double>(min_duration_ns_) / ns_per_iter);
        }
        if (max_iterations_ < 1) max_iterations_ = 1;
        if (max_iterations_ > 1'000'000'000LL) max_iterations_ = 1'000'000'000LL;

        calibrated_ = true;
        iterations_ = 0;
        total_ns_ = 0.0;
        iter_times_.clear();
        iter_times_.reserve(static_cast<size_t>(
            std::min(max_iterations_, static_cast<int64_t>(100000))));

        start_time_ = std::chrono::high_resolution_clock::now();
        iter_start_ = start_time_;
        running_ = true;
        return true;
    }

    // Record the time for the previous iteration
    if (running_ && iterations_ > 0) {
        auto now = std::chrono::high_resolution_clock::now();
        double iter_ns = std::chrono::duration<double, std::nano>(
            now - iter_start_).count();
        total_ns_ += iter_ns;
        if (iter_times_.size() < 100000) {
            iter_times_.push_back(iter_ns);
        }
    }

    iterations_++;

    if (iterations_ > max_iterations_) {
        running_ = false;
        return false;
    }

    // Check wall-clock time
    auto now = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::nano>(
        now - start_time_).count();

    if (elapsed >= static_cast<double>(min_duration_ns_) && iterations_ >= 10) {
        running_ = false;
        return false;
    }

    iter_start_ = now;
    return true;
}

void BenchState::pause_timing() {
    if (running_) {
        auto now = std::chrono::high_resolution_clock::now();
        double iter_ns = std::chrono::duration<double, std::nano>(
            now - iter_start_).count();
        total_ns_ += iter_ns;
        if (iter_times_.size() < 100000) {
            iter_times_.push_back(iter_ns);
        }
        running_ = false;
    }
}

void BenchState::resume_timing() {
    iter_start_ = std::chrono::high_resolution_clock::now();
    running_ = true;
}

void BenchState::set_bytes_per_iteration(size_t bytes) {
    bytes_per_iter_ = bytes;
}

void BenchState::set_name(const std::string& name) {
    name_ = name;
}

BenchResult BenchState::get_result() const {
    BenchResult result;
    result.name = name_;
    result.iterations = iterations_;
    result.total_ns = total_ns_;

    if (iterations_ > 0) {
        result.avg_ns = total_ns_ / static_cast<double>(iterations_);
        result.throughput = 1e9 / result.avg_ns;
    }

    if (!iter_times_.empty()) {
        auto sorted = iter_times_;
        std::sort(sorted.begin(), sorted.end());

        result.min_ns = sorted.front();
        result.max_ns = sorted.back();
        result.median_ns = sorted[sorted.size() / 2];

        // Standard deviation
        double mean = result.avg_ns;
        double variance = 0.0;
        for (double t : sorted) {
            double diff = t - mean;
            variance += diff * diff;
        }
        variance /= static_cast<double>(sorted.size());
        result.stddev_ns = std::sqrt(variance);
    }

    result.bytes_processed = bytes_per_iter_ * static_cast<size_t>(iterations_);
    if (result.bytes_processed > 0 && result.total_ns > 0.0) {
        result.bandwidth_mbps = static_cast<double>(result.bytes_processed) /
                                 result.total_ns * 1e9 / 1e6;
    }

    return result;
}

// ============================================================================
// BenchRunner
// ============================================================================

BenchRunner& BenchRunner::instance() {
    static BenchRunner runner;
    return runner;
}

void BenchRunner::add(const std::string& name, const std::string& group,
                       BenchFn fn, int priority) {
    entries_.push_back({name, group, std::move(fn), priority});
}

BenchResult BenchRunner::run_entry(const BenchEntry& entry) {
    BenchState state(min_duration_ns_);
    state.set_name(entry.name);
    entry.fn(state);
    return state.get_result();
}

void BenchRunner::run_all() {
    // Sort by group then priority
    auto sorted = entries_;
    std::sort(sorted.begin(), sorted.end(),
        [](const BenchEntry& a, const BenchEntry& b) {
            if (a.group != b.group) return a.group < b.group;
            return a.priority < b.priority;
        });

    std::vector<BenchResult> results;
    results.reserve(sorted.size());

    if (format_ == "console") {
        BenchResult::print_header();
    }

    std::string current_group;
    for (const auto& entry : sorted) {
        if (format_ == "console" && entry.group != current_group) {
            current_group = entry.group;
            std::printf("\n[%s]\n", current_group.c_str());
        }

        auto result = run_entry(entry);
        results.push_back(result);

        if (format_ == "console") {
            result.print();
        }
    }

    if (format_ == "csv") {
        print_csv(results);
    } else if (format_ == "json") {
        print_json(results);
    }
}

void BenchRunner::run_filter(const std::string& filter) {
    if (format_ == "console") {
        BenchResult::print_header();
    }

    std::vector<BenchResult> results;

    for (const auto& entry : entries_) {
        if (entry.name.find(filter) != std::string::npos ||
            entry.group.find(filter) != std::string::npos) {
            auto result = run_entry(entry);
            results.push_back(result);

            if (format_ == "console") {
                result.print();
            }
        }
    }

    if (format_ == "csv") {
        print_csv(results);
    } else if (format_ == "json") {
        print_json(results);
    }
}

BenchResult BenchRunner::run_single(const std::string& name) {
    for (const auto& entry : entries_) {
        if (entry.name == name) {
            return run_entry(entry);
        }
    }
    return BenchResult{};
}

std::vector<std::string> BenchRunner::list() const {
    std::vector<std::string> names;
    names.reserve(entries_.size());
    for (const auto& e : entries_) {
        names.push_back(e.group + "/" + e.name);
    }
    return names;
}

void BenchRunner::print_csv(const std::vector<BenchResult>& results) const {
    std::printf("name,iterations,avg_ns,min_ns,max_ns,median_ns,"
                "stddev_ns,throughput,bytes,bandwidth_mbps\n");
    for (const auto& r : results) {
        std::printf("%s,%lld,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%zu,%.1f\n",
                    r.name.c_str(),
                    static_cast<long long>(r.iterations),
                    r.avg_ns, r.min_ns, r.max_ns, r.median_ns,
                    r.stddev_ns, r.throughput,
                    r.bytes_processed, r.bandwidth_mbps);
    }
}

void BenchRunner::print_json(const std::vector<BenchResult>& results) const {
    std::printf("[\n");
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        std::printf("  {\"name\":\"%s\",\"iterations\":%lld,"
                    "\"avg_ns\":%.1f,\"min_ns\":%.1f,\"max_ns\":%.1f,"
                    "\"median_ns\":%.1f,\"stddev_ns\":%.1f,"
                    "\"throughput\":%.1f,"
                    "\"bytes\":%zu,\"bandwidth_mbps\":%.1f}%s\n",
                    r.name.c_str(),
                    static_cast<long long>(r.iterations),
                    r.avg_ns, r.min_ns, r.max_ns, r.median_ns,
                    r.stddev_ns, r.throughput,
                    r.bytes_processed, r.bandwidth_mbps,
                    (i + 1 < results.size()) ? "," : "");
    }
    std::printf("]\n");
}

} // namespace bench
} // namespace flow
