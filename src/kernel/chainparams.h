// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Network-specific chain parameters.
// Each network (mainnet, testnet, regtest) has its own set of parameters
// including genesis block, magic bytes, ports, DNS seeds, and consensus
// rules. This module consolidates all network-specific constants into
// a single ChainParams struct with factory methods for each network.
//
// The selected network's params are accessible globally via params()
// after calling select_params().

#ifndef FLOWCOIN_KERNEL_CHAINPARAMS_H
#define FLOWCOIN_KERNEL_CHAINPARAMS_H

#include "consensus/params.h"
#include "primitives/block.h"
#include "util/arith_uint256.h"
#include "util/types.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace flow::kernel {

// ============================================================================
// ChainParams
// ============================================================================

struct ChainParams {
    // ---- Network identity --------------------------------------------------

    /// Human-readable network name.
    std::string network_name;   // "mainnet", "testnet", "regtest"

    /// Magic bytes for message framing (4 bytes).
    uint32_t magic = 0;

    /// Default P2P port.
    uint16_t default_port = 0;

    /// Default RPC port.
    uint16_t rpc_port = 0;

    /// Bech32m human-readable prefix for addresses.
    const char* hrp = "";

    /// Wire protocol version.
    uint32_t protocol_version = consensus::PROTOCOL_VERSION;

    /// BIP-44 coin type for HD derivation.
    uint32_t bip44_coin_type = consensus::BIP44_COIN_TYPE;

    // ---- Genesis block -----------------------------------------------------

    /// The genesis block (created once, cached).
    CBlock genesis_block;

    /// Expected genesis block hash.
    uint256 genesis_hash;

    // ---- Consensus rules ---------------------------------------------------

    /// Initial difficulty (compact nBits).
    uint32_t initial_nbits = consensus::INITIAL_NBITS;

    /// Target time between blocks (seconds).
    int64_t target_block_time = consensus::TARGET_BLOCK_TIME;

    /// Number of blocks between difficulty retargets.
    int retarget_interval = consensus::RETARGET_INTERVAL;

    /// Expected timespan for a retarget period (seconds).
    int64_t retarget_timespan = consensus::RETARGET_TIMESPAN;

    /// Maximum difficulty change factor per retarget.
    int max_retarget_factor = consensus::MAX_RETARGET_FACTOR;

    // ---- Monetary policy ---------------------------------------------------

    /// Initial block reward (atomic units).
    Amount initial_reward = consensus::INITIAL_REWARD;

    /// Blocks between halvings.
    int halving_interval = consensus::HALVING_INTERVAL;

    /// Maximum total supply (atomic units).
    Amount max_supply = consensus::MAX_SUPPLY;

    // ---- Validation --------------------------------------------------------

    /// Assume-valid block hash: skip signature verification for all
    /// ancestors of this block. Empty = verify everything.
    uint256 assume_valid;

    /// Maximum allowed difficulty target (easiest).
    arith_uint256 pow_limit;

    /// Number of confirmations before coinbase is spendable.
    int coinbase_maturity = consensus::COINBASE_MATURITY;

    /// Maximum block size in bytes.
    size_t max_block_size = consensus::MAX_BLOCK_SIZE;

    /// Maximum transaction size in bytes.
    size_t max_tx_size = consensus::MAX_TX_SIZE;

    /// Maximum sigops per block.
    int max_block_sigops = consensus::MAX_BLOCK_SIGOPS;

    // ---- Network -----------------------------------------------------------
    // Seed nodes for P2P discovery live in src/net/seeds.h — this struct
    // does not duplicate them. The networking layer reads them directly
    // via flow::GetSeeds() / flow::GetDNSSeeds().

    /// Checkpoint blocks: (height, hash) pairs.
    /// During IBD, only chains that include these checkpoints are accepted.
    std::vector<std::pair<uint64_t, uint256>> checkpoints;

    // ---- Feature flags -----------------------------------------------------

    /// Allow minimum-difficulty blocks (regtest mode).
    bool allow_min_difficulty = false;

    /// Disable difficulty retargeting (regtest mode).
    bool no_retargeting = false;

    /// Require standard transaction types (mainnet = true).
    bool require_standard = true;

    /// Default to enabling the transaction index.
    bool default_txindex = false;

    // ---- Factory methods ---------------------------------------------------

    /// Create mainnet parameters.
    static ChainParams mainnet();

    /// Create testnet parameters.
    static ChainParams testnet();

    /// Create regtest parameters.
    static ChainParams regtest();

    /// Get parameters by network name.
    static const ChainParams& get(const std::string& network);
};

// ============================================================================
// Global parameter selection
// ============================================================================

/// Get the currently selected chain parameters.
/// Must call select_params() first.
const ChainParams& params();

/// Select the active network parameters.
/// @param network  "mainnet", "testnet", or "regtest"
void select_params(const std::string& network);

} // namespace flow::kernel

#endif // FLOWCOIN_KERNEL_CHAINPARAMS_H
