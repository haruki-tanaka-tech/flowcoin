// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "assembler.h"
#include "crypto/sign.h"
#include "crypto/address.h"
#include "core/hash.h"
#include "core/time.h"

#include <spdlog/spdlog.h>

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
    h.val_loss = tip->val_loss;
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

    // Coinbase
    Amount subsidy = consensus::get_block_subsidy(h.height);
    auto mempool_txs = mempool.get_sorted(max_txs);
    tmpl.total_fees = Amount{0};
    for (const auto& tx : mempool_txs) {
        tmpl.block.vtx.push_back(tx);
    }

    Amount total_reward = subsidy + tmpl.total_fees;
    auto coinbase = make_coinbase(total_reward, miner_key->pubkey_hash, h.height);
    tmpl.block.vtx.insert(tmpl.block.vtx.begin(), coinbase);

    h.merkle_root = tmpl.block.compute_merkle_root();

    return tmpl;
}

// ─── Proof-of-Training mining ─────────────────────────────────
//
// Each training step modifies model weights → new delta_hash.
// H = Keccak256(delta_hash || dataset_hash)
// If H < target → block valid AND model improved.
// P(valid per step) = target / 2^256 — identical to Bitcoin.

bool mine_with_training(CBlock& block, Trainer& trainer,
                         const std::vector<int32_t>& training_data,
                         uint32_t max_steps) {
    auto& h = block.header;

    for (uint32_t step = 0; step < max_steps; ++step) {
        // Train one step — this modifies the model weights
        auto result = trainer.train_step(training_data, training_data);

        // Update block header with training results
        h.val_loss = result.loss_after;
        h.train_steps = step + 1;

        // Delta hash = hash of weight changes
        h.delta_hash = keccak256(
            reinterpret_cast<const uint8_t*>(result.weight_deltas.data()),
            result.weight_deltas.size());

        // Store delta in block
        block.delta_payload = result.weight_deltas;

        // Check: H = Keccak256(D || V) < target?
        Keccak256Hasher hasher;
        hasher.update(h.delta_hash.bytes(), 32);
        hasher.update(h.dataset_hash.bytes(), 32);
        Hash256 training_hash = hasher.finalize();

        if (consensus::meets_target(training_hash, h.nbits)) {
            spdlog::debug("PoT: valid hash found after {} training steps, "
                          "loss: {:.4f} → {:.4f}",
                          step + 1, result.loss_before, result.loss_after);
            return true;
        }
    }

    return false;
}

// ─── Brute-force mining (regtest only) ────────────────────────

bool mine_brute_force(CBlock& block, uint32_t max_attempts) {
    auto& h = block.header;

    for (uint32_t i = 0; i < max_attempts; ++i) {
        uint8_t nonce_data[12];
        write_le32(nonce_data, i);
        write_le64(nonce_data + 4, h.height);
        h.delta_hash = keccak256(nonce_data, sizeof(nonce_data));

        Keccak256Hasher hasher;
        hasher.update(h.delta_hash.bytes(), 32);
        hasher.update(h.dataset_hash.bytes(), 32);
        Hash256 training_hash = hasher.finalize();

        if (consensus::meets_target(training_hash, h.nbits)) {
            return true;
        }
    }

    return false;
}

} // namespace flow::mining
