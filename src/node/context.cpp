// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "node/context.h"
#include "consensus/params.h"

namespace flow {

uint32_t NodeContext::get_magic() const {
    if (regtest) return consensus::REGTEST_MAGIC;
    if (testnet) return consensus::TESTNET_MAGIC;
    return consensus::MAINNET_MAGIC;
}

uint16_t NodeContext::get_port() const {
    if (regtest) return consensus::REGTEST_PORT;
    if (testnet) return consensus::TESTNET_PORT;
    return consensus::MAINNET_PORT;
}

uint16_t NodeContext::get_rpc_port() const {
    if (regtest) return consensus::REGTEST_RPC_PORT;
    if (testnet) return consensus::TESTNET_RPC_PORT;
    return consensus::MAINNET_RPC_PORT;
}

const char* NodeContext::get_hrp() const {
    if (regtest) return consensus::REGTEST_HRP;
    if (testnet) return consensus::TESTNET_HRP;
    return consensus::MAINNET_HRP;
}

} // namespace flow
