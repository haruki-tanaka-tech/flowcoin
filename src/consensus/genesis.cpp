// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Genesis block creation and verification implementation.

#include "genesis.h"
#include "merkle.h"
#include "params.h"
#include "reward.h"
#include "../hash/keccak.h"
#include "../hash/merkle.h"

#include <cstring>
#include <mutex>

namespace flow::consensus {

// ---------------------------------------------------------------------------
// create_genesis_block
// ---------------------------------------------------------------------------

CBlock create_genesis_block() {
    CBlock genesis;

    // -- Header fields --
    genesis.prev_hash.set_null();
    genesis.height      = 0;
    genesis.timestamp   = GENESIS_TIMESTAMP;
    genesis.nbits       = INITIAL_NBITS;
    genesis.nonce        = 1;  // v2 network
    genesis.version     = 1;

    genesis.miner_pubkey.fill(0);
    genesis.miner_sig.fill(0);

    // -- Coinbase transaction --
    CTransaction coinbase;
    coinbase.version = 1;
    coinbase.locktime = 0;

    CTxIn cb_in;
    cb_in.prevout.txid.set_null();
    cb_in.prevout.index = 0;
    cb_in.signature.fill(0);

    const char* msg = GENESIS_COINBASE_MSG;
    size_t msg_len = std::strlen(msg);
    uint256 msg_hash = keccak256(reinterpret_cast<const uint8_t*>(msg), msg_len);
    std::memcpy(cb_in.pubkey.data(), msg_hash.data(), 32);

    coinbase.vin.push_back(cb_in);

    CTxOut cb_out;
    cb_out.amount = INITIAL_REWARD;
    cb_out.pubkey_hash.fill(0);
    coinbase.vout.push_back(cb_out);

    genesis.vtx.push_back(coinbase);

    // Compute merkle root
    std::vector<uint256> txids;
    txids.push_back(coinbase.get_txid());
    genesis.merkle_root = compute_merkle_root(txids);

    return genesis;
}

// ---------------------------------------------------------------------------
// compute_genesis_hash
// ---------------------------------------------------------------------------

uint256 compute_genesis_hash() {
    CBlock genesis = create_genesis_block();
    return genesis.get_hash();
}

// ---------------------------------------------------------------------------
// get_genesis_hash
// ---------------------------------------------------------------------------

const uint256& get_genesis_hash() {
    static uint256 cached_hash = []() {
        return compute_genesis_hash();
    }();
    return cached_hash;
}

// ---------------------------------------------------------------------------
// verify_genesis_hash
// ---------------------------------------------------------------------------

bool verify_genesis_hash(const uint256& hash) {
    return hash == get_genesis_hash();
}

// ---------------------------------------------------------------------------
// validate_genesis_block
// ---------------------------------------------------------------------------

bool validate_genesis_block(const CBlock& genesis) {
    // 1. prev_hash must be null
    if (!genesis.prev_hash.is_null()) {
        return false;
    }

    // 2. height must be 0
    if (genesis.height != 0) {
        return false;
    }

    // 3. timestamp must match GENESIS_TIMESTAMP
    if (genesis.timestamp != GENESIS_TIMESTAMP) {
        return false;
    }

    // 4. nbits must match INITIAL_NBITS
    if (genesis.nbits != INITIAL_NBITS) {
        return false;
    }

    // 5. Must have exactly one transaction (coinbase)
    if (genesis.vtx.size() != 1) {
        return false;
    }

    // 6. First transaction must be coinbase
    if (!genesis.vtx[0].is_coinbase()) {
        return false;
    }

    // 7. Coinbase output amount must equal INITIAL_REWARD
    if (genesis.vtx[0].get_value_out() != INITIAL_REWARD) {
        return false;
    }

    // 8. Merkle root must match
    std::vector<uint256> txids;
    txids.push_back(genesis.vtx[0].get_txid());
    uint256 expected_root = compute_merkle_root(txids);
    if (genesis.merkle_root != expected_root) {
        return false;
    }

    // 9. Block hash must match hardcoded genesis hash
    uint256 block_hash = genesis.get_hash();
    if (block_hash != get_genesis_hash()) {
        return false;
    }

    // 10. Miner sig must be all zeros (no real miner for genesis)
    for (size_t i = 0; i < 64; ++i) {
        if (genesis.miner_sig[i] != 0) return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// create_testnet_genesis_block
// ---------------------------------------------------------------------------

CBlock create_testnet_genesis_block() {
    CBlock genesis = create_genesis_block();

    genesis.timestamp = GENESIS_TIMESTAMP + 86400;
    genesis.nonce = 1;

    std::vector<uint256> txids;
    for (const auto& tx : genesis.vtx) {
        txids.push_back(tx.get_txid());
    }
    genesis.merkle_root = compute_merkle_root(txids);

    return genesis;
}

// ---------------------------------------------------------------------------
// create_regtest_genesis_block
// ---------------------------------------------------------------------------

CBlock create_regtest_genesis_block() {
    CBlock genesis = create_genesis_block();

    genesis.timestamp = GENESIS_TIMESTAMP + 172800;
    genesis.nonce = 2;
    genesis.nbits = INITIAL_NBITS;

    std::vector<uint256> txids;
    for (const auto& tx : genesis.vtx) {
        txids.push_back(tx.get_txid());
    }
    genesis.merkle_root = compute_merkle_root(txids);

    return genesis;
}

// ---------------------------------------------------------------------------
// create_genesis_for_network
// ---------------------------------------------------------------------------

CBlock create_genesis_for_network(NetworkType network) {
    switch (network) {
        case NetworkType::TESTNET:
            return create_testnet_genesis_block();
        case NetworkType::REGTEST:
            return create_regtest_genesis_block();
        case NetworkType::MAINNET:
        default:
            return create_genesis_block();
    }
}

// ---------------------------------------------------------------------------
// compute_genesis_hash_for_network
// ---------------------------------------------------------------------------

uint256 compute_genesis_hash_for_network(NetworkType network) {
    CBlock genesis = create_genesis_for_network(network);
    return genesis.get_hash();
}

// ---------------------------------------------------------------------------
// get_genesis_info
// ---------------------------------------------------------------------------

GenesisInfo get_genesis_info(NetworkType network) {
    CBlock genesis = create_genesis_for_network(network);

    GenesisInfo info;
    info.hash = genesis.get_hash();
    info.merkle_root = genesis.merkle_root;
    info.timestamp = genesis.timestamp;
    info.nbits = genesis.nbits;
    info.nonce = genesis.nonce;
    info.coinbase_value = genesis.vtx.empty() ? 0 : genesis.vtx[0].get_value_out();
    info.coinbase_message = GENESIS_COINBASE_MSG;

    return info;
}

} // namespace flow::consensus
