// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// NodeContext: top-level container that owns all subsystems of a running
// FlowCoin node. Wires together the chain state, wallet, network manager,
// RPC server, mempool, and consensus model into a single lifetime scope.

#ifndef FLOWCOIN_NODE_CONTEXT_H
#define FLOWCOIN_NODE_CONTEXT_H

#include <cstdint>
#include <memory>
#include <string>

namespace flow {

class ChainState;
class Wallet;
class NetManager;
class RpcServer;
class Mempool;
class ConsensusModel;

struct NodeContext {
    std::unique_ptr<ChainState> chain;
    std::unique_ptr<Wallet> wallet;
    std::unique_ptr<NetManager> net;
    std::unique_ptr<RpcServer> rpc;
    std::unique_ptr<Mempool> mempool;
    std::unique_ptr<ConsensusModel> model;

    std::string datadir;
    bool testnet = false;
    bool regtest = false;

    // Get the network magic bytes based on network type
    uint32_t get_magic() const;

    // Get the P2P port based on network type
    uint16_t get_port() const;

    // Get the RPC port based on network type
    uint16_t get_rpc_port() const;

    // Get the Bech32m human-readable prefix based on network type
    const char* get_hrp() const;
};

} // namespace flow

#endif // FLOWCOIN_NODE_CONTEXT_H
