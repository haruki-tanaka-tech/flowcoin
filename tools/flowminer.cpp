// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// FlowCoin miner — mines blocks using Proof-of-Training.
// mainnet/testnet: real SGD training via ggml (each step = one "nonce attempt")
// regtest: brute-force nonce for instant blocks (testing only)

#include "node/context.h"
#include "mining/assembler.h"
#include "mining/trainer.h"
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
    bool is_regtest = (network == flow::consensus::Network::REGTEST);

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

    node.start_rpc("127.0.0.1", rpc_port);
    if (enable_p2p) {
        flow::net::NetConfig p2p_config;
        p2p_config.port = (p2p_port != 0) ? p2p_port : params.p2p_port;
        p2p_config.seed_nodes = seed_nodes;
        node.start_p2p(p2p_config);
    }

    // Initialize trainer for real PoT mining (not used in regtest)
    std::unique_ptr<flow::mining::Trainer> trainer;
    std::vector<int32_t> training_data;
    if (!is_regtest) {
        uint32_t d_model = flow::consensus::GENESIS_D_MODEL;
        uint32_t d_ff = flow::consensus::GENESIS_D_FF;
        uint32_t vocab = 256; // byte-level for v0.1
        trainer = std::make_unique<flow::mining::Trainer>(d_model, d_ff, vocab);

        // Training data: simple repeating pattern for v0.1
        // Production: miners provide their own training data
        for (int i = 0; i < 128; ++i) {
            training_data.push_back(i % vocab);
        }
        spdlog::info("Trainer initialized: d_model={}, d_ff={}, vocab={}", d_model, d_ff, vocab);
    }

    spdlog::info("Chain height: {}, Wallet keys: {}",
        node.chain->height(), node.wallet->key_count());

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    uint64_t blocks_mined = 0;

    while (!g_shutdown.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        auto tmpl = flow::mining::assemble_block(*node.chain, *node.mempool, *node.wallet);

        spdlog::info("Mining block {} to {}...",
            tmpl.block.header.height, tmpl.miner_address);

        bool mined = false;
        if (is_regtest) {
            mined = flow::mining::mine_brute_force(tmpl.block);
        } else {
            mined = flow::mining::mine_with_training(tmpl.block, *trainer, training_data);
        }

        if (!mined) {
            spdlog::warn("Failed to mine block {}", tmpl.block.header.height);
            continue;
        }

        // Sign the block
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

            spdlog::info("Block {} mined! Hash: {} loss: {:.4f} steps: {} (total: {})",
                tmpl.block.header.height,
                tmpl.block.get_hash().to_hex().substr(0, 16),
                tmpl.block.header.val_loss,
                tmpl.block.header.train_steps,
                blocks_mined);

            if (node.net_manager && node.net_manager->peer_count() > 0) {
                flow::VectorWriter inv_msg;
                inv_msg.write_compact_size(1);
                inv_msg.write_u32(static_cast<uint32_t>(flow::net::InvType::BLOCK));
                auto hash = tmpl.block.get_hash();
                inv_msg.write_bytes(std::span<const uint8_t>(hash.bytes(), 32));
                node.net_manager->broadcast(flow::net::cmd::INV, inv_msg.release());
            }
        } else {
            spdlog::error("Block rejected: {}", state.reject_reason);
        }
    }

    spdlog::info("Miner stopped. Blocks mined: {}", blocks_mined);
    node.shutdown();
    return 0;
}
