// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// FlowCoin standalone miner entry point.
// Connects to a running flowcoind, trains ResonanceNet V5 on local data,
// and submits blocks via JSON-RPC.

#include "miner/miner.h"
#include "version.h"

#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <string>

static flow::miner::MinerEngine* g_miner = nullptr;

static void signal_handler(int sig) {
    (void)sig;
    if (g_miner) g_miner->stop();
}

static void print_usage() {
    std::printf(
        "\n"
        "  FlowCoin Miner v%s\n"
        "  Native C++ | ResonanceNet V5 | Proof-of-Training\n\n"
        "  Usage: flowcoin-miner [options]\n\n"
        "  Options:\n"
        "    --datadir <path>       Data directory (default: ~/.flowcoin)\n"
        "    --rpcport <port>       Node RPC port (default: 9334)\n"
        "    --rpcuser <user>       RPC username\n"
        "    --rpcpassword <pass>   RPC password\n"
        "    --backend <name>       Compute backend: auto, cpu, cuda, vulkan, metal, opencl\n"
        "    --lr <float>           Learning rate (default: 0.001)\n"
        "    --seq-len <int>        Sequence length (default: 256)\n"
        "    --help                 Show this help\n\n"
        "  The miner reads flowcoin.conf from the data directory for\n"
        "  RPC credentials. Place training data (.txt or .bin files)\n"
        "  in <datadir>/training/.\n\n",
        flow::version::CLIENT_VERSION_STRING
    );
}

static bool parse_args(flow::miner::MinerConfig& config, int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage();
            return false;
        }

        auto require_value = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: %s requires a value\n", name);
                std::exit(1);
            }
            return argv[++i];
        };

        if (arg == "--datadir") {
            config.datadir = require_value("--datadir");
        } else if (arg == "--rpcport") {
            config.rpc_port = std::atoi(require_value("--rpcport"));
        } else if (arg == "--rpcuser") {
            config.rpc_user = require_value("--rpcuser");
        } else if (arg == "--rpcpassword") {
            config.rpc_password = require_value("--rpcpassword");
        } else if (arg == "--backend") {
            config.backend = require_value("--backend");
        } else if (arg == "--cpu") {
            config.backend = "cpu";
        } else if (arg == "--lr") {
            config.learning_rate = std::strtof(require_value("--lr"), nullptr);
        } else if (arg == "--seq-len") {
            config.seq_len = std::atoi(require_value("--seq-len"));
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            std::fprintf(stderr, "Use --help for usage information.\n");
            return false;
        }
    }

    return true;
}

// Default data directory
static std::string default_datadir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata) return std::string(appdata) + "\\FlowCoin";
    return "C:\\FlowCoin";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if (home) return std::string(home) + "/Library/Application Support/FlowCoin";
    return "/tmp/flowcoin";
#else
    const char* home = std::getenv("HOME");
    if (home) return std::string(home) + "/.flowcoin";
    return "/tmp/flowcoin";
#endif
}

// Read flowcoin.conf for RPC settings
static void read_config(flow::miner::MinerConfig& config) {
    std::string conf_path = config.datadir + "/flowcoin.conf";
    FILE* f = std::fopen(conf_path.c_str(), "r");
    if (!f) return;

    char line[512];
    while (std::fgets(line, sizeof(line), f)) {
        // Strip comments
        char* hash = std::strchr(line, '#');
        if (hash) *hash = '\0';

        // Find key=value
        char* eq = std::strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        const char* key = line;
        const char* val = eq + 1;

        // Trim
        while (*key == ' ' || *key == '\t') ++key;
        while (*val == ' ' || *val == '\t') ++val;

        // Remove trailing whitespace from key
        char* key_end = eq - 1;
        while (key_end > key && (*key_end == ' ' || *key_end == '\t')) {
            *key_end = '\0';
            --key_end;
        }

        // Remove trailing newline/whitespace from val
        size_t vlen = std::strlen(val);
        while (vlen > 0 && (val[vlen - 1] == '\n' || val[vlen - 1] == '\r' ||
               val[vlen - 1] == ' ' || val[vlen - 1] == '\t')) {
            const_cast<char*>(val)[vlen - 1] = '\0';
            --vlen;
        }

        if (std::strcmp(key, "rpcuser") == 0 && config.rpc_user.empty()) {
            config.rpc_user = val;
        } else if (std::strcmp(key, "rpcpassword") == 0 && config.rpc_password.empty()) {
            config.rpc_password = val;
        } else if (std::strcmp(key, "rpcport") == 0) {
            config.rpc_port = std::atoi(val);
        }
    }

    std::fclose(f);
}

int main(int argc, char* argv[]) {
    std::printf("\n  FlowCoin Miner v%s\n", flow::version::CLIENT_VERSION_STRING);
    std::printf("  Native C++ | ResonanceNet V5\n\n");

    flow::miner::MinerConfig config;

    // Set default datadir
    config.datadir = default_datadir();

    // Parse command-line arguments first (they override config file)
    if (!parse_args(config, argc, argv)) {
        return 0;  // --help was shown
    }

    // Read config file for defaults
    read_config(config);

    // Install signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    flow::miner::MinerEngine miner(config);
    g_miner = &miner;

    if (!miner.init()) {
        std::fprintf(stderr, "Miner initialization failed.\n");
        return 1;
    }

    miner.run();
    g_miner = nullptr;

    auto s = miner.stats();
    std::printf("\n  Session ended.\n");
    std::printf("  Steps: %llu | Checks: %llu | Blocks: %llu\n",
                static_cast<unsigned long long>(s.total_steps),
                static_cast<unsigned long long>(s.total_checks),
                static_cast<unsigned long long>(s.blocks_found));
    return 0;
}
