// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Register all RPC methods on a server instance.

#pragma once

#include "server.h"
#include "chain/chainstate.h"
#include "mempool/mempool.h"
#include "wallet/wallet.h"

namespace flow::rpc {

// Blockchain RPCs: getblockcount, getbestblockhash, getblock, gettraininginfo
void register_blockchain_rpcs(RpcServer& server, ChainState& chain);

// Mempool RPCs: getmempoolinfo
void register_mempool_rpcs(RpcServer& server, Mempool& mempool);

// Wallet RPCs: getnewaddress, getbalance, listaddresses, importprivkey, dumpwallet
void register_wallet_rpcs(RpcServer& server, Wallet& wallet, ChainState& chain);

} // namespace flow::rpc
