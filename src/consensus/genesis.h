// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Genesis block creation and verification.
//
// The genesis block is the hardcoded root of every FlowCoin chain.
// It contains the initial coinbase transaction with the genesis message,
// the initial model architecture dimensions, and a null miner identity
// (no real miner for genesis).
//
// On first startup, every node independently creates the genesis block
// from these parameters and verifies that its hash matches the hardcoded
// GENESIS_HASH. This ensures all nodes agree on block 0.

#ifndef FLOWCOIN_CONSENSUS_GENESIS_H
#define FLOWCOIN_CONSENSUS_GENESIS_H

#include "params.h"
#include "../primitives/block.h"
#include "../util/types.h"

namespace flow::consensus {

/// Create the genesis block with all consensus parameters.
///
/// Builds the coinbase transaction, sets all header fields from
/// GENESIS_* constants, computes the merkle root, and returns
/// the complete block.
///
/// The genesis block has:
///   - prev_hash:    null (no parent)
///   - height:       0
///   - timestamp:    GENESIS_TIMESTAMP (2026-03-21 00:00:00 UTC)
///   - nbits:        INITIAL_NBITS (easiest difficulty)
///   - val_loss:     MAX_VAL_LOSS (untrained model)
///   - miner_pubkey: all zeros (no real miner)
///   - miner_sig:    all zeros (no signature)
///   - coinbase msg: GENESIS_COINBASE_MSG
///   - coinbase out: INITIAL_REWARD to null pubkey_hash
CBlock create_genesis_block();

/// Compute the hash of the genesis block.
/// Creates the genesis block and returns its keccak256d hash.
uint256 compute_genesis_hash();

/// Verify that a given hash matches the expected genesis hash.
/// Returns true if the hash equals compute_genesis_hash().
bool verify_genesis_hash(const uint256& hash);

/// Hardcoded genesis block hash.
/// This is computed once from create_genesis_block() and embedded here
/// so that nodes can verify genesis integrity without recomputing the
/// full block on every startup.
///
/// The actual value is populated in genesis.cpp by computing
/// keccak256d of the genesis block's unsigned header data.
extern const uint256& get_genesis_hash();

/// Genesis model hash: keccak256 of the initial model weights.
/// Used to verify that all nodes start with identical model state.
/// The actual value is populated in genesis.cpp by initializing
/// a ConsensusModel with GENESIS_SEED and hashing its weights.
extern const uint256& get_genesis_model_hash();

/// Validate the genesis block's internal consistency.
/// Checks:
///   1. prev_hash is null
///   2. height is 0
///   3. timestamp matches GENESIS_TIMESTAMP
///   4. nbits matches INITIAL_NBITS
///   5. Exactly one transaction (coinbase)
///   6. Coinbase is_coinbase() is true
///   7. Coinbase output amount equals INITIAL_REWARD
///   8. Merkle root matches computed merkle root
///   9. Architecture dimensions match GENESIS_* constants
///  10. Block hash matches hardcoded GENESIS_HASH
///
/// Returns true if all checks pass.
bool validate_genesis_block(const CBlock& genesis);

/// Get the genesis coinbase message as a string.
inline const char* genesis_coinbase_message() {
    return GENESIS_COINBASE_MSG;
}

/// Get the genesis timestamp.
inline int64_t genesis_timestamp() {
    return GENESIS_TIMESTAMP;
}

/// Create the testnet genesis block.
/// Same structure as mainnet but with different timestamp and nonce
/// to produce a different hash, preventing testnet/mainnet confusion.
CBlock create_testnet_genesis_block();

/// Create the regtest genesis block.
/// Uses easiest difficulty and a different timestamp.
CBlock create_regtest_genesis_block();

/// Network type for genesis block selection.
enum class NetworkType {
    MAINNET,
    TESTNET,
    REGTEST
};

/// Create a genesis block for the specified network.
CBlock create_genesis_for_network(NetworkType network);

/// Compute the genesis hash for a specific network.
uint256 compute_genesis_hash_for_network(NetworkType network);

/// Get a human-readable description of the genesis block parameters.
/// Useful for debugging and RPC output.
struct GenesisInfo {
    uint256 hash;
    uint256 merkle_root;
    int64_t timestamp;
    uint32_t nbits;
    float val_loss;
    uint32_t d_model;
    uint32_t n_layers;
    Amount coinbase_value;
    std::string coinbase_message;
};

/// Extract genesis block info for display.
GenesisInfo get_genesis_info(NetworkType network = NetworkType::MAINNET);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_GENESIS_H
