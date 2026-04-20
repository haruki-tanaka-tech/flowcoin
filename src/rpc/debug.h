// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Debug and diagnostic RPC methods for development and testing.
// These methods provide low-level access to internal state.

#ifndef FLOWCOIN_RPC_DEBUG_H
#define FLOWCOIN_RPC_DEBUG_H

namespace flow {

class RpcServer;
class ChainState;
class Mempool;
class Wallet;

/// Register debug/diagnostic RPC methods with the server.
void register_debug_rpcs(RpcServer& server, ChainState& chain,
                         Mempool& mempool, Wallet& wallet);

} // namespace flow

#endif // FLOWCOIN_RPC_DEBUG_H
