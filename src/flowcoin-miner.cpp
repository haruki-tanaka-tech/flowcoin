// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// flowcoin-miner: standalone training miner for FlowCoin.
// Reads training data from ~/.flowcoin/training/, connects to flowcoind
// via JSON-RPC, trains the ResonanceNet V5 model using ggml, and submits
// blocks when the training hash meets the difficulty target.

#include "mining/gpu_miner.h"
#include "version.h"

#include <cstdio>
#include <csignal>
#include <cstdlib>
#include <string>

static flow::GPUMiner* g_miner = nullptr;

static void signal_handler(int) {
    if (g_miner) g_miner->stop();
}

static void print_banner() {
    printf("\n");
    printf("  FlowCoin Miner v%s\n", flow::version::CLIENT_VERSION_STRING);
    printf("  ggml backend | ResonanceNet V5\n");
    printf("\n");
}

static void print_usage() {
    printf("Usage: flowcoin-miner [options]\n\n");
    printf("Options:\n");
    printf("  --datadir <path>    Data directory (default: ~/.flowcoin)\n");
    printf("  --rpcport <port>    Node RPC port (default: 9334)\n");
    printf("  --rpcuser <user>    RPC username\n");
    printf("  --rpcpassword <pw>  RPC password\n");
    printf("  --cpu               Force CPU (default: auto-detect GPU)\n");
    printf("  --threads <n>       CPU threads (default: auto)\n");
    printf("  --help              Show this help\n");
    printf("\n");
    printf("Training data: place .txt or .bin files in <datadir>/training/\n");
    printf("The miner reads all files from that directory automatically.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  flowcoin-miner\n");
    printf("  flowcoin-miner --rpcuser flowcoin --rpcpassword pass123\n");
    printf("  flowcoin-miner --cpu --threads 8\n");
}

int main(int argc, char* argv[]) {
    print_banner();

    flow::MinerConfig config;

    // Parse minimal args
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { print_usage(); return 0; }
        else if (arg == "--datadir" && i + 1 < argc) config.datadir = argv[++i];
        else if (arg == "--rpcport" && i + 1 < argc) config.rpc_port = std::stoi(argv[++i]);
        else if (arg == "--rpcuser" && i + 1 < argc) config.rpc_user = argv[++i];
        else if (arg == "--rpcpassword" && i + 1 < argc) config.rpc_password = argv[++i];
        else if (arg == "--cpu") config.force_cpu = true;
        else if (arg == "--threads" && i + 1 < argc) config.n_threads = std::stoi(argv[++i]);
        else {
            fprintf(stderr, "Unknown option: %s\n\n", arg.c_str());
            print_usage();
            return 1;
        }
    }

    // Default datadir
    if (config.datadir.empty()) {
        const char* home = getenv("HOME");
        if (home) config.datadir = std::string(home) + "/.flowcoin";
        else config.datadir = ".";
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    flow::GPUMiner miner(config);
    g_miner = &miner;

    if (!miner.init()) {
        fprintf(stderr, "Miner initialization failed.\n");
        return 1;
    }

    miner.run();
    g_miner = nullptr;

    auto stats = miner.get_stats();
    printf("\n  Session ended.\n");
    printf("  Steps: %lu | Checks: %lu | Blocks: %lu\n",
           static_cast<unsigned long>(stats.total_steps),
           static_cast<unsigned long>(stats.hash_checks),
           static_cast<unsigned long>(stats.blocks_found));
    return 0;
}
