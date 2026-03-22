// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "assembler.h"
#include "crypto/sign.h"
#include "crypto/address.h"
#include "core/hash.h"
#include "core/time.h"

namespace flow::mining {

BlockTemplate assemble_block(ChainState& chain,
                              Mempool& mempool,
                              Wallet& wallet,
                              size_t max_txs) {
    BlockTemplate tmpl;
    const CBlockIndex* tip = chain.tip();

    auto& h = tmpl.block.header;
    h.prev_hash = tip->hash;
    h.height = tip->height + 1;
    h.timestamp = std::max(get_time(), tip->timestamp + consensus::MIN_BLOCK_INTERVAL);
    h.prev_val_loss = tip->val_loss;
    h.val_loss = tip->val_loss; // will be updated after real training
    h.nbits = tip->nbits;
    h.train_steps = 0;

    // Growth fields
    uint32_t improving = tip->improving_blocks;
    auto dims = consensus::compute_growth(h.height, improving);
    h.d_model = dims.d_model;
    h.n_layers = dims.n_layers;
    h.d_ff = dims.d_ff;
    h.n_experts = dims.n_experts;
    h.n_heads = dims.n_heads;
    h.rank = dims.rank;

    // Dataset hash (fixed for now)
    h.dataset_hash = Hash256::ZERO;

    // Fresh mining address — NEVER reuse
    tmpl.miner_address = wallet.get_mining_address();
    const WalletKey* miner_key = nullptr;
    for (const auto& wk : wallet.get_all_keys()) {
        if (wk.address == tmpl.miner_address) {
            miner_key = &wk;
            break;
        }
    }

    h.miner_pubkey = miner_key->keypair.pubkey;

    // Coinbase reward
    Amount subsidy = consensus::get_block_subsidy(h.height);

    // Collect mempool transactions
    auto mempool_txs = mempool.get_sorted(max_txs);
    tmpl.total_fees = Amount{0};
    for (const auto& tx : mempool_txs) {
        // Fee calculation would require UTXO lookup.
        // For now, include txs without fee tracking.
        tmpl.block.vtx.push_back(tx);
    }

    Amount total_reward = subsidy + tmpl.total_fees;

    // Coinbase tx (first transaction)
    auto coinbase = make_coinbase(total_reward, miner_key->pubkey_hash, h.height);
    tmpl.block.vtx.insert(tmpl.block.vtx.begin(), coinbase);

    // Merkle root
    h.merkle_root = tmpl.block.compute_merkle_root();

    return tmpl;
}

bool try_mine(CBlock& block, uint32_t max_attempts) {
    auto& h = block.header;

    for (uint32_t i = 0; i < max_attempts; ++i) {
        // Generate candidate delta_hash
        uint8_t nonce_data[12];
        write_le32(nonce_data, i);
        write_le64(nonce_data + 4, h.height);
        h.delta_hash = keccak256(nonce_data, sizeof(nonce_data));

        // H = Keccak256(D || V) per whitepaper §3
        Keccak256Hasher hasher;
        hasher.update(h.delta_hash.bytes(), 32);
        hasher.update(h.dataset_hash.bytes(), 32);
        Hash256 training_hash = hasher.finalize();

        if (consensus::meets_target(training_hash, h.nbits)) {
            // Update merkle root (delta_hash changed doesn't affect it,
            // but we need to re-sign since unsigned bytes changed)
            // Actually delta_hash IS in the unsigned portion, so re-sign:
            // (miner_pubkey must already be set)
            // Caller is responsible for signing after try_mine succeeds.
            return true;
        }
    }

    return false;
}

} // namespace flow::mining
