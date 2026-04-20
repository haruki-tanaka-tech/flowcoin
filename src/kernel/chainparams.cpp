// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "kernel/chainparams.h"
#include "consensus/difficulty.h"
#include "consensus/genesis.h"

#include <cassert>
#include <cstdio>
#include <stdexcept>

namespace flow::kernel {

// ============================================================================
// Mainnet parameters
// ============================================================================

ChainParams ChainParams::mainnet() {
    ChainParams p;
    p.network_name = "mainnet";
    p.magic = consensus::MAINNET_MAGIC;
    p.default_port = consensus::MAINNET_PORT;
    p.rpc_port = consensus::MAINNET_RPC_PORT;
    p.hrp = consensus::MAINNET_HRP;

    // Genesis block
    p.genesis_block = consensus::create_genesis_block();
    p.genesis_hash = p.genesis_block.get_hash();

    // Consensus
    p.initial_nbits = consensus::INITIAL_NBITS;
    p.target_block_time = consensus::TARGET_BLOCK_TIME;
    p.retarget_interval = consensus::RETARGET_INTERVAL;
    p.retarget_timespan = consensus::RETARGET_TIMESPAN;
    p.max_retarget_factor = consensus::MAX_RETARGET_FACTOR;

    // Monetary
    p.initial_reward = consensus::INITIAL_REWARD;
    p.halving_interval = consensus::HALVING_INTERVAL;
    p.max_supply = consensus::MAX_SUPPLY;

    // Validation
    // assume_valid left empty for now (no blocks mined yet)
    arith_uint256 pow_limit;
    consensus::derive_target(consensus::INITIAL_NBITS, pow_limit);
    p.pow_limit = pow_limit;
    p.coinbase_maturity = consensus::COINBASE_MATURITY;

    // Seed discovery: see src/net/seeds.h (single source of truth).

    // Feature flags
    p.allow_min_difficulty = false;
    p.no_retargeting = false;
    p.require_standard = true;

    return p;
}

// ============================================================================
// Testnet parameters
// ============================================================================

ChainParams ChainParams::testnet() {
    ChainParams p;
    p.network_name = "testnet";
    p.magic = consensus::TESTNET_MAGIC;
    p.default_port = consensus::TESTNET_PORT;
    p.rpc_port = consensus::TESTNET_RPC_PORT;
    p.hrp = consensus::TESTNET_HRP;

    // Genesis block (same as mainnet)
    p.genesis_block = consensus::create_genesis_block();
    p.genesis_hash = p.genesis_block.get_hash();

    // Consensus (same as mainnet)
    p.initial_nbits = consensus::INITIAL_NBITS;
    p.target_block_time = consensus::TARGET_BLOCK_TIME;
    p.retarget_interval = consensus::RETARGET_INTERVAL;
    p.retarget_timespan = consensus::RETARGET_TIMESPAN;
    p.max_retarget_factor = consensus::MAX_RETARGET_FACTOR;

    // Monetary (same as mainnet)
    p.initial_reward = consensus::INITIAL_REWARD;
    p.halving_interval = consensus::HALVING_INTERVAL;
    p.max_supply = consensus::MAX_SUPPLY;

    // Validation
    arith_uint256 pow_limit;
    consensus::derive_target(consensus::INITIAL_NBITS, pow_limit);
    p.pow_limit = pow_limit;
    p.coinbase_maturity = consensus::COINBASE_MATURITY;

    // Seed discovery: see src/net/seeds.h.

    // Feature flags: testnet allows min difficulty blocks after 20 minutes
    p.allow_min_difficulty = true;
    p.no_retargeting = false;
    p.require_standard = false;

    return p;
}

// ============================================================================
// Regtest parameters
// ============================================================================

ChainParams ChainParams::regtest() {
    ChainParams p;
    p.network_name = "regtest";
    p.magic = consensus::REGTEST_MAGIC;
    p.default_port = consensus::REGTEST_PORT;
    p.rpc_port = consensus::REGTEST_RPC_PORT;
    p.hrp = consensus::REGTEST_HRP;

    // Genesis block (same structure)
    p.genesis_block = consensus::create_genesis_block();
    p.genesis_hash = p.genesis_block.get_hash();

    // Consensus
    p.initial_nbits = consensus::INITIAL_NBITS;
    p.target_block_time = consensus::TARGET_BLOCK_TIME;
    p.retarget_interval = consensus::RETARGET_INTERVAL;
    p.retarget_timespan = consensus::RETARGET_TIMESPAN;
    p.max_retarget_factor = consensus::MAX_RETARGET_FACTOR;

    // Monetary
    p.initial_reward = consensus::INITIAL_REWARD;
    p.halving_interval = 150;  // Short halving for testing
    p.max_supply = consensus::MAX_SUPPLY;

    // Validation
    arith_uint256 pow_limit;
    consensus::derive_target(consensus::INITIAL_NBITS, pow_limit);
    p.pow_limit = pow_limit;
    p.coinbase_maturity = consensus::COINBASE_MATURITY;

    // Seed discovery: regtest has no seeds (see src/net/seeds.h).

    // Feature flags: regtest allows everything
    p.allow_min_difficulty = true;
    p.no_retargeting = true;
    p.require_standard = false;
    p.default_txindex = true;

    return p;
}

// ============================================================================
// Parameter lookup by name
// ============================================================================

const ChainParams& ChainParams::get(const std::string& network) {
    if (network == "mainnet" || network == "main") {
        static ChainParams mainnet_params = mainnet();
        return mainnet_params;
    }
    if (network == "testnet" || network == "test") {
        static ChainParams testnet_params = testnet();
        return testnet_params;
    }
    if (network == "regtest") {
        static ChainParams regtest_params = regtest();
        return regtest_params;
    }
    throw std::runtime_error("Unknown network: " + network);
}

// ============================================================================
// Global parameter selection
// ============================================================================

static const ChainParams* g_selected_params = nullptr;

const ChainParams& params() {
    assert(g_selected_params != nullptr &&
           "select_params() must be called before params()");
    return *g_selected_params;
}

void select_params(const std::string& network) {
    g_selected_params = &ChainParams::get(network);
}

} // namespace flow::kernel
