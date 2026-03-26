// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Genesis block creation and verification.

#ifndef FLOWCOIN_CONSENSUS_GENESIS_H
#define FLOWCOIN_CONSENSUS_GENESIS_H

#include "params.h"
#include "../primitives/block.h"
#include "../util/types.h"

namespace flow::consensus {

/// Create the genesis block with all consensus parameters.
CBlock create_genesis_block();

/// Compute the hash of the genesis block.
uint256 compute_genesis_hash();

/// Verify that a given hash matches the expected genesis hash.
bool verify_genesis_hash(const uint256& hash);

/// Hardcoded genesis block hash (cached singleton).
extern const uint256& get_genesis_hash();

/// Validate the genesis block's internal consistency.
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
CBlock create_testnet_genesis_block();

/// Create the regtest genesis block.
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

/// Genesis block info for display.
struct GenesisInfo {
    uint256 hash;
    uint256 merkle_root;
    int64_t timestamp;
    uint32_t nbits;
    uint32_t nonce;
    Amount coinbase_value;
    std::string coinbase_message;
};

/// Extract genesis block info for display.
GenesisInfo get_genesis_info(NetworkType network = NetworkType::MAINNET);

} // namespace flow::consensus

#endif // FLOWCOIN_CONSENSUS_GENESIS_H
