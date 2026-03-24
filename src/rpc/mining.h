// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Mining RPC methods: getblocktemplate, submitblock, getmininginfo.

#ifndef FLOWCOIN_RPC_MINING_H
#define FLOWCOIN_RPC_MINING_H

namespace flow {

class RpcServer;
class ChainState;
class NetManager;

/// Register all mining-related RPC methods with the server.
void register_mining_rpcs(RpcServer& server, ChainState& chain, NetManager& net);

} // namespace flow

#endif // FLOWCOIN_RPC_MINING_H
