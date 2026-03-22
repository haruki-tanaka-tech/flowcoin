// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "params.h"

namespace flow::consensus {

const ChainParams& ChainParams::mainnet() {
    static const ChainParams p{
        .network       = Network::MAINNET,
        .name          = "mainnet",
        .magic         = 0x464C4F57,        // "FLOW"
        .p2p_port      = 9333,
        .rpc_port      = 9334,
        .hrp           = "fl",
        .initial_nbits = 0x1e0fffff,
        .seed_nodes    = {
            "seed.flowcoin.org:9333",
        },
        .fallback_nodes = {
            "211.205.13.203:9333",
        },
    };
    return p;
}

const ChainParams& ChainParams::testnet() {
    static const ChainParams p{
        .network       = Network::TESTNET,
        .name          = "testnet",
        .magic         = 0x544E4554,
        .p2p_port      = 19333,
        .rpc_port      = 19334,
        .hrp           = "tfl",
        .initial_nbits = 0x1f0fffff,
        .seed_nodes    = {
            "seed.flowcoin.org:19333",
        },
        .fallback_nodes = {},
    };
    return p;
}

const ChainParams& ChainParams::regtest() {
    static const ChainParams p{
        .network       = Network::REGTEST,
        .name          = "regtest",
        .magic         = 0x52454754,
        .p2p_port      = 29333,
        .rpc_port      = 29334,
        .hrp           = "flrt",
        .initial_nbits = 0x207fffff,
        .seed_nodes    = {},
        .fallback_nodes = {},
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
