// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Training-specific RPC methods: gettraininginfo, getmodelweights,
// getmodelhash, getdeltapayload, getgrowthschedule, getvalidationdata.

#ifndef FLOWCOIN_RPC_TRAINING_H
#define FLOWCOIN_RPC_TRAINING_H

namespace flow {

class RpcServer;
class ChainState;

/// Register all training/model-related RPC methods with the server.
void register_training_rpcs(RpcServer& server, ChainState& chain);

} // namespace flow

#endif // FLOWCOIN_RPC_TRAINING_H
