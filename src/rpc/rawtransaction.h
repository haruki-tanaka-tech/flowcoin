// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Raw transaction RPC methods: getrawtransaction, createrawtransaction,
// decoderawtransaction, sendrawtransaction, gettransaction.

#ifndef FLOWCOIN_RPC_RAWTRANSACTION_H
#define FLOWCOIN_RPC_RAWTRANSACTION_H

namespace flow {

class RpcServer;
class ChainState;
class Mempool;
class Wallet;
class NetManager;

/// Register all raw-transaction-related RPC methods with the server.
void register_rawtx_rpcs(RpcServer& server, ChainState& chain,
                          Mempool& mempool, Wallet& wallet, NetManager& net);

} // namespace flow

#endif // FLOWCOIN_RPC_RAWTRANSACTION_H
