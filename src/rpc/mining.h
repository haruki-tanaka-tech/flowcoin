// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Mining RPC methods: getblocktemplate, submitblock, getmininginfo.

#ifndef FLOWCOIN_RPC_MINING_H
#define FLOWCOIN_RPC_MINING_H

namespace flow {

class RpcServer;
class ChainState;
class NetManager;
class Wallet;

class Mempool;

/// Register all mining-related RPC methods with the server.
void register_mining_rpcs(RpcServer& server, ChainState& chain, NetManager& net, Wallet* wallet = nullptr);

/// Register mempool-aware mining RPCs (getblocktemplate with tx selection).
void register_mining_mempool_rpcs(RpcServer& server, ChainState& chain,
                                   Mempool& mempool, NetManager& net);

} // namespace flow

#endif // FLOWCOIN_RPC_MINING_H
