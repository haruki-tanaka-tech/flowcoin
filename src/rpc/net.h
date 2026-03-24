// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Network RPC methods: getpeerinfo, getconnectioncount, addnode,
// disconnectnode, getnetworkinfo, getnettotals, listbanned,
// setban, clearbanned, ping, getaddednodeinfo.

#ifndef FLOWCOIN_RPC_NET_H
#define FLOWCOIN_RPC_NET_H

namespace flow {

class RpcServer;
class NetManager;

/// Register all network-related RPC methods with the server.
void register_net_rpcs(RpcServer& server, NetManager& net);

} // namespace flow

#endif // FLOWCOIN_RPC_NET_H
