// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// FlowCoin miner — mines blocks using Proof-of-Training.
// Usage: flowminer [-regtest] [-datadir DIR] [-wallet SEED] [-addnode ip:port]

#include "node/context.h"
#include "mining/assembler.h"
#include "crypto/sign.h"
#include "core/time.h"
#include "net/protocol.h"

#include <spdlog/spdlog.h>
#include <csignal>
#include <filesystem>

static std::atomic<bool> g_shutdown{false};
static void signal_handler(int) { g_shutdown.store(true); }

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::info);

    std::string data_dir;
    std::string seed_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    auto network = flow::consensus::Network::MAINNET;
    uint16_t p2p_port = 0;
    uint16_t rpc_port = 0;
    std::vector<std::string> seed_nodes;
    bool enable_p2p = true;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-regtest") network = flow::consensus::Network::REGTEST;
        else if (arg == "-testnet") network = flow::consensus::Network::TESTNET;
        else if (arg == "-datadir" && i + 1 < argc) data_dir = argv[++i];
        else if (arg == "-wallet" && i + 1 < argc) seed_hex = argv[++i];
        else if (arg == "-port" && i + 1 < argc) p2p_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (arg == "-rpcport" && i + 1 < argc) rpc_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (arg == "-addnode" && i + 1 < argc) seed_nodes.push_back(argv[++i]);
        else if (arg == "-nop2p") enable_p2p = false;
        else if (arg[0] != '-') data_dir = arg;
    }

    auto& params = flow::consensus::ChainParams::get(network);

    if (data_dir.empty()) {
        auto home = std::filesystem::path(getenv("HOME") ? getenv("HOME") : ".");
        data_dir = home / ".flowcoin";
        if (network != flow::consensus::Network::MAINNET) {
            data_dir += "/" + params.name;
        }
    }

    spdlog::info("FlowMiner v0.1.0 [{}]", params.name);

    flow::NodeContext node;
    node.init(data_dir, network, seed_hex);

    // Start RPC + P2P
    node.start_rpc("127.0.0.1", rpc_port);

    if (enable_p2p) {
        flow::net::NetConfig p2p_config;
        p2p_config.port = (p2p_port != 0) ? p2p_port : params.p2p_port;
        p2p_config.seed_nodes = seed_nodes;
        node.start_p2p(p2p_config);
    }

    spdlog::info("Chain height: {}, Wallet keys: {}",
        node.chain->height(), node.wallet->key_count());

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    uint64_t blocks_mined = 0;

    while (!g_shutdown.load()) {
        // Brief yield to let RPC/P2P threads process
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        auto tmpl = flow::mining::assemble_block(*node.chain, *node.mempool, *node.wallet);

        spdlog::info("Mining block {} to {}...",
            tmpl.block.header.height, tmpl.miner_address);

        if (!flow::mining::try_mine(tmpl.block)) {
            spdlog::warn("Failed to mine block {}", tmpl.block.header.height);
            continue;
        }

        // Sign
        const auto* miner_key = node.wallet->find_key(
            [&]() {
                flow::Blob<20> pkh;
                auto full = flow::keccak256d(tmpl.block.header.miner_pubkey.bytes(), 32);
                std::memcpy(pkh.bytes(), full.bytes(), 20);
                return pkh;
            }());

        if (miner_key) {
            auto ub = tmpl.block.header.unsigned_bytes();
            tmpl.block.header.miner_sig = flow::crypto::sign(
                miner_key->keypair.privkey, miner_key->keypair.pubkey,
                ub.data(), ub.size());
        }

        auto state = node.chain->accept_block(tmpl.block);
        if (state.valid) {
            blocks_mined++;
            node.mempool->remove_for_block(tmpl.block.vtx);

            spdlog::info("Block {} mined! Hash: {} (total: {})",
                tmpl.block.header.height,
                tmpl.block.get_hash().to_hex().substr(0, 16),
                blocks_mined);

            // Broadcast to peers
            if (node.net_manager && node.net_manager->peer_count() > 0) {
                flow::VectorWriter inv_msg;
                inv_msg.write_compact_size(1);
                inv_msg.write_u32(static_cast<uint32_t>(flow::net::InvType::BLOCK));
                auto hash = tmpl.block.get_hash();
                inv_msg.write_bytes(std::span<const uint8_t>(hash.bytes(), 32));
                node.net_manager->broadcast(flow::net::cmd::INV, inv_msg.release());
                spdlog::info("Broadcast to {} peers", node.net_manager->peer_count());
            }
        } else {
            spdlog::error("Block rejected: {}", state.reject_reason);
        }
    }

    spdlog::info("Miner stopped. Blocks mined: {}", blocks_mined);
    node.shutdown();
    return 0;
}
