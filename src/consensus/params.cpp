// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "params.h"

namespace flow::consensus {

const ChainParams& ChainParams::mainnet() {
    static const ChainParams p{
        .network      = Network::MAINNET,
        .name         = "mainnet",
        .magic        = 0x464C4F57,        // "FLOW"
        .p2p_port     = 9333,
        .rpc_port     = 9334,
        .hrp          = "fl",
        .initial_nbits = 0x1e0fffff,       // hard: ~10 min with real training
    };
    return p;
}

const ChainParams& ChainParams::testnet() {
    static const ChainParams p{
        .network      = Network::TESTNET,
        .name         = "testnet",
        .magic        = 0x544E4554,        // "TNET"
        .p2p_port     = 19333,
        .rpc_port     = 19334,
        .hrp          = "tfl",
        .initial_nbits = 0x1f0fffff,       // easier than mainnet
    };
    return p;
}

const ChainParams& ChainParams::regtest() {
    static const ChainParams p{
        .network      = Network::REGTEST,
        .name         = "regtest",
        .magic        = 0x52454754,        // "REGT"
        .p2p_port     = 29333,
        .rpc_port     = 29334,
        .hrp          = "flrt",
        .initial_nbits = 0x207fffff,       // trivial: instant blocks for testing
    };
    return p;
}

const ChainParams& ChainParams::get(Network net) {
    switch (net) {
        case Network::TESTNET: return testnet();
        case Network::REGTEST: return regtest();
        default: return mainnet();
    }
}

} // namespace flow::consensus
