// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Wallet RPC methods: getnewaddress, getbalance, listunspent,
// sendtoaddress, listtransactions, validateaddress, importprivkey,
// dumpprivkey, dumpwallet, importwallet, backupwallet, encryptwallet,
// walletpassphrase, walletlock, signmessage, verifymessage,
// getaddressinfo, listaddresses.

#ifndef FLOWCOIN_RPC_WALLET_H
#define FLOWCOIN_RPC_WALLET_H

namespace flow {

class RpcServer;
class Wallet;
class ChainState;
class NetManager;

/// Register all wallet-related RPC methods with the server.
void register_wallet_rpcs(RpcServer& server, Wallet& wallet,
                          ChainState& chain, NetManager& net);

} // namespace flow

#endif // FLOWCOIN_RPC_WALLET_H
