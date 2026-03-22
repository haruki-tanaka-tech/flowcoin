// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// FlowCoin full node daemon.
// Usage: flowcoind [-regtest] [-testnet] [-datadir DIR] [-wallet SEED]

#include "node/context.h"
#include "consensus/params.h"
#include <spdlog/spdlog.h>

#include <csignal>
#include <filesystem>
#include <thread>

static std::atomic<bool> g_shutdown{false};
static void signal_handler(int) { g_shutdown.store(true); }

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::info);

    std::string data_dir;
    std::string wallet_seed;
    auto network = flow::consensus::Network::MAINNET;
    uint16_t rpc_port = 0; // 0 = use network default
    uint16_t p2p_port = 0;
    std::vector<std::string> seed_nodes;
    bool enable_p2p = true;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-regtest") network = flow::consensus::Network::REGTEST;
        else if (arg == "-testnet") network = flow::consensus::Network::TESTNET;
        else if (arg == "-datadir" && i + 1 < argc) data_dir = argv[++i];
        else if (arg == "-wallet" && i + 1 < argc) wallet_seed = argv[++i];
        else if (arg == "-rpcport" && i + 1 < argc) rpc_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (arg == "-port" && i + 1 < argc) p2p_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (arg == "-addnode" && i + 1 < argc) seed_nodes.push_back(argv[++i]);
        else if (arg == "-nop2p") enable_p2p = false;
        else if (arg[0] != '-') data_dir = arg;
    }

    auto& params = flow::consensus::ChainParams::get(network);

    if (data_dir.empty()) {
#ifdef _WIN32
        const char* home_env = getenv("USERPROFILE");
#else
        const char* home_env = getenv("HOME");
#endif
        auto home = std::filesystem::path(home_env ? home_env : ".");
        data_dir = (home / ".flowcoin").string();
        if (network != flow::consensus::Network::MAINNET) {
            data_dir += "/" + params.name;
        }
    }

    spdlog::info("FlowCoin v0.1.0 [{}]", params.name);

    flow::NodeContext node;
    node.init(data_dir, network, wallet_seed);

    spdlog::info("Chain height: {}", node.chain->height());

    // RPC
    node.start_rpc("127.0.0.1", rpc_port);

    // P2P
    if (enable_p2p) {
        flow::net::NetConfig p2p_config;
        p2p_config.port = (p2p_port != 0) ? p2p_port : params.p2p_port;
        p2p_config.seed_nodes = seed_nodes;
        node.start_p2p(p2p_config);
    }

    if (node.wallet) {
        spdlog::info("Wallet: {} keys", node.wallet->key_count());
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    spdlog::info("Node running. Press Ctrl+C to stop.");

    while (!g_shutdown.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    spdlog::info("Shutting down...");
    node.shutdown();
    spdlog::info("Shutdown complete.");
    return 0;
}
