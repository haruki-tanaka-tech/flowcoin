// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// All consensus parameters in one place.
// Three network modes: mainnet, testnet, regtest.

#pragma once

#include "core/types.h"
#include <cstdint>
#include <string>

namespace flow::consensus {

// ─── Constants (same across all networks) ────────────────────
constexpr int64_t COIN                = 100'000'000LL;
constexpr int64_t MAX_SUPPLY          = 21'000'000LL * COIN;
constexpr int64_t INITIAL_REWARD      = 50LL * COIN;
constexpr int64_t MIN_REWARD          = 1LL;
constexpr int     HALVING_INTERVAL    = 210'000;
constexpr int64_t TARGET_BLOCK_TIME   = 600;           // 10 minutes
constexpr int64_t MIN_BLOCK_INTERVAL  = 300;           // 5 minutes
constexpr int64_t MAX_FUTURE_TIME     = 7200;          // 2 hours
constexpr int     RETARGET_INTERVAL   = 2016;
constexpr int64_t RETARGET_TIMESPAN   = 14 * 24 * 60 * 60; // 2 weeks
constexpr int     MAX_RETARGET_FACTOR = 4;
constexpr int     EVAL_BATCHES        = 20;
constexpr float   MAX_VAL_LOSS        = 1000.0f;
constexpr float   MAX_LOSS_REGRESSION = 2.0f;
constexpr size_t  MAX_DELTA_SIZE      = 100'000'000;
constexpr uint32_t GENESIS_D_MODEL    = 512;
constexpr uint32_t GENESIS_N_LAYERS   = 8;
constexpr uint32_t GENESIS_N_HEADS    = 8;
constexpr uint32_t GENESIS_D_FF       = 1'024;
constexpr uint32_t GENESIS_N_EXPERTS  = 1'024;
constexpr uint32_t GENESIS_RANK       = 64;
constexpr float    GENESIS_VAL_LOSS   = 10.0f;
constexpr uint32_t MAX_D_MODEL        = 1'024;
constexpr uint32_t MAX_N_LAYERS       = 24;
constexpr uint32_t MAX_N_EXPERTS      = 65'536;
constexpr uint32_t DIM_GROWTH_PHASE   = 500;
constexpr uint32_t BASE_EXPERT_GROWTH = 4;
constexpr uint8_t  KECCAK_PAD         = 0x01;
constexpr uint32_t BIP44_COIN_TYPE    = 9555;
constexpr size_t  MAX_BLOCK_SIZE      = 4'000'000;
constexpr size_t  MAX_TX_SIZE         = 1'000'000;
constexpr int     MAX_PEERS           = 125;
constexpr int     FINALITY_DEPTH      = 6;
constexpr int64_t GENESIS_TIMESTAMP   = 1742515200;    // 21 Mar 2026 00:00:00 UTC
constexpr uint32_t PROTOCOL_VERSION   = 1;

// ─── Network-specific parameters ─────────────────────────────

enum class Network { MAINNET, TESTNET, REGTEST };

struct ChainParams {
    Network     network;
    std::string name;
    uint32_t    magic;
    uint16_t    p2p_port;
    uint16_t    rpc_port;
    std::string hrp;           // bech32m human-readable prefix
    uint32_t    initial_nbits; // genesis difficulty

    static const ChainParams& mainnet();
    static const ChainParams& testnet();
    static const ChainParams& regtest();
    static const ChainParams& get(Network net);
};

// ─── Convenience: default to mainnet (backward compat) ───────
constexpr uint32_t MAINNET_MAGIC     = 0x464C4F57;  // "FLOW"
constexpr uint16_t MAINNET_PORT      = 9333;
constexpr uint16_t MAINNET_RPC_PORT  = 9334;
// Initial mainnet difficulty: requires ~2^16 training steps per block
// Bitcoin genesis was 0x1d00ffff. Ours starts harder to ensure 10 min.
constexpr uint32_t INITIAL_NBITS     = 0x1e0fffff;

} // namespace flow::consensus
