// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Blockchain RPC methods: getblockcount, getbestblockhash, getblockhash,
// getblock, getblockheader, getblockchaininfo, gettxout,
// gettxoutsetinfo, verifychain, getrawmempool, getmempoolinfo.

#ifndef FLOWCOIN_RPC_BLOCKCHAIN_H
#define FLOWCOIN_RPC_BLOCKCHAIN_H

namespace flow {

class RpcServer;
class ChainState;
class Mempool;

/// Register all blockchain-related RPC methods with the server.
void register_blockchain_rpcs(RpcServer& server, ChainState& chain);

/// Register extended blockchain RPCs (getdifficulty, getblockfilter, etc).
void register_extended_blockchain_rpcs(RpcServer& server, ChainState& chain);

/// Register mempool-related RPCs (requires both chain and mempool).
void register_mempool_rpcs(RpcServer& server, ChainState& chain, Mempool& mempool);

} // namespace flow

#endif // FLOWCOIN_RPC_BLOCKCHAIN_H
