// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Utility RPC methods: help, stop, uptime, getinfo, validateaddress,
// signmessagewithprivkey, logging, echo, getmemoryinfo.

#ifndef FLOWCOIN_RPC_UTIL_H
#define FLOWCOIN_RPC_UTIL_H

namespace flow {

class RpcServer;
class ChainState;
class Wallet;
class NetManager;
class Mempool;

/// Register all utility RPC methods with the server.
void register_util_rpcs(RpcServer& server, ChainState& chain,
                        Wallet& wallet, NetManager& net, Mempool& mempool);

} // namespace flow

#endif // FLOWCOIN_RPC_UTIL_H
