// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Training-related RPC commands (stub -- PoW consensus, no training).

#include "rpc/training.h"
#include "rpc/server.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "consensus/params.h"
#include "consensus/pow.h"
#include "hash/keccak.h"
#include "util/strencodings.h"

#include <stdexcept>

namespace flow {

// All training RPC commands return stub data in PoW mode.

} // namespace flow
