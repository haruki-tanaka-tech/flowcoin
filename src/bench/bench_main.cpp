// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Benchmark runner entry point. Supports running all benchmarks,
// filtering by name, listing available benchmarks, and setting
// iteration counts.

#include "bench.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

static void print_usage(const char* argv0) {
    std::cerr << "Usage: " << argv0 << " [OPTIONS]\n"
              << "\nOptions:\n"
              << "  --list              List all registered benchmarks\n"
              << "  --filter=NAME       Run benchmarks matching NAME\n"
              << "  --bench=NAME        Run a single benchmark by exact name\n"
              << "  --iters=N           Set iteration count (default: 1000)\n"
              << "  --help              Show this help message\n"
              << "\nExamples:\n"
              << "  " << argv0 << "                      Run all benchmarks\n"
              << "  " << argv0 << " --filter=Keccak      Run Keccak benchmarks\n"
              << "  " << argv0 << " --bench=Keccak256_1KB --iters=5000\n";
}

int main(int argc, char* argv[]) {
    int iterations = 1000;
    std::string filter;
    std::string bench_name;
    bool list_only = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        if (arg == "--list") {
            list_only = true;
            continue;
        }
        if (arg.rfind("--filter=", 0) == 0) {
            filter = arg.substr(9);
            continue;
        }
        if (arg.rfind("--bench=", 0) == 0) {
            bench_name = arg.substr(8);
            continue;
        }
        if (arg.rfind("--iters=", 0) == 0) {
            iterations = std::atoi(arg.substr(8).c_str());
            if (iterations <= 0) {
                std::cerr << "Invalid iteration count: " << arg.substr(8) << "\n";
                return 1;
            }
            continue;
        }
        std::cerr << "Unknown option: " << arg << "\n";
        print_usage(argv[0]);
        return 1;
    }

    auto& runner = flow::bench::BenchRunner::instance();

    if (list_only) {
        auto names = runner.list();
        for (const auto& n : names) {
            std::cout << n << "\n";
        }
        return 0;
    }

    runner.set_min_duration(static_cast<int64_t>(iterations) * 1000000LL);

    if (!bench_name.empty()) {
        runner.run_single(bench_name);
    } else if (!filter.empty()) {
        runner.run_filter(filter);
    } else {
        runner.run_all();
    }

    return 0;
}
