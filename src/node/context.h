// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// NodeContext: owns all components of a FlowCoin node.

#pragma once

#include "chain/chainstate.h"
#include "mempool/mempool.h"
#include "wallet/wallet.h"
#include "rpc/server.h"
#include "rpc/http_server.h"
#include "rpc/methods.h"
#include "net/netman.h"
#include "net/messages.h"
#include "consensus/params.h"

#include <memory>
#include <string>

namespace flow {

struct NodeContext {
    const consensus::ChainParams* params{nullptr};

    std::unique_ptr<ChainState> chain;
    std::unique_ptr<Mempool> mempool;
    std::unique_ptr<Wallet> wallet;
    std::unique_ptr<rpc::RpcServer> rpc_server;
    std::unique_ptr<rpc::HttpServer> http_server;
    std::unique_ptr<net::NetManager> net_manager;
    std::unique_ptr<net::MessageHandler> msg_handler;

    // Initialize all components.
    void init(const std::string& data_dir,
              consensus::Network network = consensus::Network::MAINNET,
              const std::string& wallet_seed = "");

    // Start the HTTP RPC server on localhost.
    void start_rpc(const std::string& bind_addr = "127.0.0.1", uint16_t port = 0);

    // Start the P2P network.
    void start_p2p(const net::NetConfig& config = {});

    // Shutdown and flush.
    void shutdown();
};

} // namespace flow
