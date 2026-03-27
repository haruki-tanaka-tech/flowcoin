// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
#include "rpc/server.h"
#include "chain/chainstate.h"

namespace flow {
void register_training_rpcs(RpcServer&, ChainState&) {
    // PoW consensus — no training RPCs
}
} // namespace flow
