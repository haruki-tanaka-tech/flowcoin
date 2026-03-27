// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#ifndef FLOWCOIN_RPC_TRAINING_H
#define FLOWCOIN_RPC_TRAINING_H

namespace flow {

class RpcServer;
class ChainState;

/// Stub — PoW consensus, no training RPCs.
void register_training_rpcs(RpcServer& server, ChainState& chain);

} // namespace flow

#endif // FLOWCOIN_RPC_TRAINING_H
