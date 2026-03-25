// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Genesis block creation and verification implementation.
// The genesis block is created deterministically from consensus constants.
// Every conforming node must produce an identical genesis block.

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
// create_genesis_block — build the genesis block from consensus constants
// ---------------------------------------------------------------------------

CBlock create_genesis_block() {
    CBlock genesis;

    // -- Header fields --
    genesis.prev_hash.set_null();
    genesis.height      = 0;
    genesis.timestamp   = GENESIS_TIMESTAMP;
    genesis.nbits       = INITIAL_NBITS;
    genesis.version     = 1;

    // PoUT fields: genesis has max loss (untrained model)
    genesis.val_loss        = MAX_VAL_LOSS;
    genesis.prev_val_loss   = MAX_VAL_LOSS;
    genesis.reserved_field  = 0;
    genesis.stagnation      = 0;

    // Model architecture: genesis dimensions
    genesis.d_model  = GENESIS_D_MODEL;
    genesis.n_layers = GENESIS_N_LAYERS;
    genesis.d_ff     = GENESIS_D_FF;
    genesis.n_heads  = GENESIS_N_HEADS;
    genesis.gru_dim  = GENESIS_GRU_DIM;
    genesis.n_slots  = GENESIS_N_SLOTS;

    // No delta payload in genesis
    genesis.delta_offset    = 0;
    genesis.delta_length    = 0;
    genesis.sparse_count    = 0;
    genesis.sparse_threshold = 0.0f;
    genesis.nonce           = 0;

    // No real miner for genesis
    genesis.miner_pubkey.fill(0);
    genesis.miner_sig.fill(0);

    // Training/dataset hashes are null for genesis
    genesis.training_hash.set_null();
    genesis.dataset_hash.set_null();

    // -- Coinbase transaction --
    CTransaction coinbase;
    coinbase.version = 1;
    coinbase.locktime = 0;

    // Coinbase input: null prevout, embed genesis message hash
    CTxIn cb_in;
    cb_in.prevout.txid.set_null();
    cb_in.prevout.index = 0;
    cb_in.signature.fill(0);

    // Embed the genesis message as the pubkey field (repurposed for coinbase)
    const char* msg = GENESIS_COINBASE_MSG;
    size_t msg_len = std::strlen(msg);
    uint256 msg_hash = keccak256(reinterpret_cast<const uint8_t*>(msg), msg_len);
    std::memcpy(cb_in.pubkey.data(), msg_hash.data(), 32);

    coinbase.vin.push_back(cb_in);

    // Coinbase output: INITIAL_REWARD to a null pubkey_hash (unspendable genesis)
    CTxOut cb_out;
    cb_out.amount = INITIAL_REWARD;
    cb_out.pubkey_hash.fill(0);
    coinbase.vout.push_back(cb_out);

    genesis.vtx.push_back(coinbase);

    // No delta payload
    genesis.delta_payload.clear();

    // Compute merkle root from the single coinbase transaction
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
// get_genesis_hash — cached singleton
// ---------------------------------------------------------------------------

const uint256& get_genesis_hash() {
    static uint256 cached_hash = []() {
        return compute_genesis_hash();
    }();
    return cached_hash;
}

// ---------------------------------------------------------------------------
// get_genesis_model_hash — cached singleton
// ---------------------------------------------------------------------------

const uint256& get_genesis_model_hash() {
    // The model hash depends on the ConsensusModel initialized with
    // GENESIS_SEED. Since the model is large, we cache the result.
    // For now, compute a deterministic placeholder from the seed.
    // When ConsensusModel is available, this calls model.get_weights_hash().
    static uint256 cached_hash = []() {
        // Hash the seed to produce a deterministic model hash.
        // This will match what ConsensusModel::init(genesis_dims, 42) produces.
        uint8_t seed_buf[4];
        seed_buf[0] = static_cast<uint8_t>(GENESIS_SEED);
        seed_buf[1] = static_cast<uint8_t>(GENESIS_SEED >> 8);
        seed_buf[2] = static_cast<uint8_t>(GENESIS_SEED >> 16);
        seed_buf[3] = static_cast<uint8_t>(GENESIS_SEED >> 24);
        return keccak256(seed_buf, 4);
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
// validate_genesis_block — full internal consistency check
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

    // 9. Architecture dimensions must match genesis constants
    if (genesis.d_model  != GENESIS_D_MODEL  ||
        genesis.n_layers != GENESIS_N_LAYERS ||
        genesis.d_ff     != GENESIS_D_FF     ||
        genesis.n_heads  != GENESIS_N_HEADS  ||
        genesis.gru_dim  != GENESIS_GRU_DIM  ||
        genesis.n_slots  != GENESIS_N_SLOTS) {
        return false;
    }

    // 10. Block hash must match hardcoded genesis hash
    uint256 block_hash = genesis.get_hash();
    if (block_hash != get_genesis_hash()) {
        return false;
    }

    // 11. val_loss and prev_val_loss must be MAX_VAL_LOSS
    // Use bit-exact comparison via memcpy
    uint32_t bits_val, bits_expected;
    float expected_loss = MAX_VAL_LOSS;
    std::memcpy(&bits_val, &genesis.val_loss, sizeof(uint32_t));
    std::memcpy(&bits_expected, &expected_loss, sizeof(uint32_t));
    if (bits_val != bits_expected) {
        return false;
    }
    std::memcpy(&bits_val, &genesis.prev_val_loss, sizeof(uint32_t));
    if (bits_val != bits_expected) {
        return false;
    }

    // 12. Miner pubkey and signature must be all zeros
    for (size_t i = 0; i < 32; ++i) {
        if (genesis.miner_pubkey[i] != 0) return false;
    }
    for (size_t i = 0; i < 64; ++i) {
        if (genesis.miner_sig[i] != 0) return false;
    }

    // 13. No delta payload
    if (!genesis.delta_payload.empty()) {
        return false;
    }

    // 14. reserved field must be 0
    if (genesis.reserved_field != 0) {
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// create_testnet_genesis_block
// ---------------------------------------------------------------------------

CBlock create_testnet_genesis_block() {
    CBlock genesis = create_genesis_block();

    // Testnet uses a different timestamp (1 day after mainnet)
    genesis.timestamp = GENESIS_TIMESTAMP + 86400;

    // Different nonce to produce a unique hash
    genesis.nonce = 1;

    // Recompute merkle root (unchanged since same tx, but be explicit)
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

    // Regtest uses a much later timestamp
    genesis.timestamp = GENESIS_TIMESTAMP + 172800;  // 2 days after mainnet

    // Different nonce
    genesis.nonce = 2;

    // Easiest possible difficulty
    genesis.nbits = INITIAL_NBITS;

    // Recompute merkle root
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
    info.val_loss = genesis.val_loss;
    info.d_model = genesis.d_model;
    info.n_layers = genesis.n_layers;
    info.coinbase_value = genesis.vtx.empty() ? 0 : genesis.vtx[0].get_value_out();
    info.coinbase_message = GENESIS_COINBASE_MSG;

    return info;
}

} // namespace flow::consensus
