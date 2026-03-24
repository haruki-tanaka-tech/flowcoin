// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "mining/blocktemplate.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "consensus/difficulty.h"
#include "util/arith_uint256.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "crypto/bech32.h"
#include "util/time.h"

#include <chrono>
#include <cstring>

namespace flow {

BlockTemplate create_block_template(const ChainState& chain,
                                     const std::string& coinbase_address) {
    BlockTemplate tmpl;
    CBlockIndex* tip = chain.tip();

    uint64_t next_height = tip ? tip->height + 1 : 0;

    // --- Fill header fields ---

    CBlockHeader& hdr = tmpl.header;
    hdr.version = 1;
    hdr.height = next_height;

    // Previous block hash
    if (tip) {
        hdr.prev_hash = tip->hash;
    } else {
        hdr.prev_hash.set_null();
    }

    // Timestamp: current wall clock time
    hdr.timestamp = GetTime();

    // Difficulty: get next required work
    if (tip && next_height > 0) {
        // For retarget calculation, we need first_block_time of the current period.
        // At a retarget boundary (height % 2016 == 0), the new target is computed.
        // Otherwise, the target stays the same as the parent's.
        if (next_height % consensus::RETARGET_INTERVAL == 0) {
            // Walk back to find the first block of this retarget period
            CBlockIndex* first = tip;
            for (int i = 0; i < consensus::RETARGET_INTERVAL - 1 && first->prev; ++i) {
                first = first->prev;
            }
            hdr.nbits = consensus::get_next_work_required(
                next_height, tip->nbits, first->timestamp, tip->timestamp);
        } else {
            hdr.nbits = tip->nbits;
        }
    } else {
        hdr.nbits = consensus::INITIAL_NBITS;
    }

    // Model dimensions at next height
    uint32_t improving_blocks = tip ? tip->improving_blocks : 0;
    tmpl.dims = consensus::compute_growth(next_height, improving_blocks);

    hdr.d_model  = tmpl.dims.d_model;
    hdr.n_layers = tmpl.dims.n_layers;
    hdr.d_ff     = tmpl.dims.d_ff;
    hdr.n_heads  = tmpl.dims.n_heads;
    hdr.gru_dim  = tmpl.dims.gru_dim;
    hdr.n_slots  = tmpl.dims.n_slots;

    // Previous val_loss (for validation continuity)
    if (tip) {
        hdr.prev_val_loss = tip->val_loss;
    } else {
        hdr.prev_val_loss = consensus::MAX_VAL_LOSS;
    }

    // Minimum training steps
    tmpl.min_train_steps = consensus::compute_min_steps(next_height);

    // Stagnation counter (incremented if parent did not improve)
    if (tip && tip->prev) {
        if (tip->val_loss >= tip->prev_val_loss) {
            hdr.stagnation = tip->stagnation_count + 1;
        } else {
            hdr.stagnation = 0;
        }
    } else {
        hdr.stagnation = 0;
    }

    // Fields left for the miner to fill:
    //   val_loss, training_hash, dataset_hash, delta_*, sparse_*, nonce,
    //   miner_pubkey, miner_sig, merkle_root

    // --- Decode target ---
    arith_uint256 target_arith;
    consensus::derive_target(hdr.nbits, target_arith);
    tmpl.target = ArithToUint256(target_arith);

    // --- Build coinbase transaction ---
    CTransaction& coinbase = tmpl.coinbase_tx;
    coinbase.version = 1;
    coinbase.locktime = 0;

    // Single coinbase input (null prevout)
    CTxIn cb_in;
    cb_in.prevout = COutPoint();  // null = coinbase
    // Encode height in the coinbase "script" (BIP34 style)
    // We just leave the pubkey/signature zero for coinbase inputs
    coinbase.vin.push_back(cb_in);

    // Coinbase output: block reward to the miner
    Amount reward = consensus::compute_block_reward(next_height);

    CTxOut cb_out;
    cb_out.amount = reward;

    // If a coinbase address is provided, decode it and set the pubkey_hash
    if (!coinbase_address.empty()) {
        auto decoded = bech32m_decode(coinbase_address);
        if (decoded.valid && decoded.program.size() == 20) {
            std::memcpy(cb_out.pubkey_hash.data(), decoded.program.data(), 20);
            // Remaining 12 bytes stay zero (20-byte program padded to 32)
        }
    }
    // If no address provided, pubkey_hash is all zeros -- miner must fill it

    coinbase.vout.push_back(cb_out);

    return tmpl;
}

} // namespace flow
