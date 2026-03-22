// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "validation.h"
#include "params.h"
#include "difficulty.h"
#include "growth.h"
#include "reward.h"
#include "crypto/sign.h"

#include <cmath>
#include <cstring>

namespace flow::consensus {

ValidationState check_block(const CBlock& block, const BlockContext& ctx) {
    ValidationState state;
    const auto& h = block.header;

    // ─── Check 1: prev_hash == parent.hash ──────────────────
    if (h.prev_hash != ctx.parent_hash) {
        state.invalid("bad-prevhash");
        return state;
    }

    // ─── Check 2: height == parent.height + 1 ───────────────
    if (h.height != ctx.parent_height + 1) {
        state.invalid("bad-height");
        return state;
    }

    // ─── Check 3: timestamp > median time past ─────────────
    // Bitcoin BIP 113: block timestamp must exceed median of last 11 blocks.
    // Falls back to parent timestamp if MTP not computed (early chain).
    {
        int64_t mtp = (ctx.median_time_past > 0) ? ctx.median_time_past : ctx.parent_timestamp;
        if (h.timestamp <= mtp) {
            state.invalid("time-too-old");
            return state;
        }
    }

    // ─── Check 4: timestamp >= parent.timestamp + 300 ───────
    if (h.timestamp < ctx.parent_timestamp + MIN_BLOCK_INTERVAL) {
        state.invalid("time-too-soon");
        return state;
    }

    // ─── Check 5: timestamp <= now + 7200 ───────────────────
    if (h.timestamp > ctx.current_time + MAX_FUTURE_TIME) {
        state.invalid("time-too-far-future");
        return state;
    }

    // ─── Check 6: isfinite(val_loss) && val_loss > 0 ────────
    if (!std::isfinite(h.val_loss) || h.val_loss <= 0.0f) {
        state.invalid("bad-val-loss");
        return state;
    }

    // ─── Check 7: val_loss < 1000.0 ─────────────────────────
    if (h.val_loss >= MAX_VAL_LOSS) {
        state.invalid("val-loss-too-high");
        return state;
    }

    // ─── Check 8: prev_val_loss == parent.val_loss (bit-identical) ─
    {
        uint32_t bits_a, bits_b;
        std::memcpy(&bits_a, &h.prev_val_loss, 4);
        std::memcpy(&bits_b, &ctx.parent_val_loss, 4);
        if (bits_a != bits_b) {
            state.invalid("bad-prev-val-loss");
            return state;
        }
    }

    // ─── Check 9: val_loss <= 2.0 * parent.val_loss ─────────
    if (h.val_loss > MAX_LOSS_REGRESSION * ctx.parent_val_loss) {
        state.invalid("val-loss-regression");
        return state;
    }

    // ─── Check 10: training_hash < difficulty_target ─────────
    // Whitepaper §3: H = Keccak256(D || V), where D = delta_hash, V = dataset_hash
    // Block valid iff H < T. P(valid) = T / 2^256, identical to Bitcoin.
    {
        Keccak256Hasher hasher;
        hasher.update(h.delta_hash.bytes(), 32);
        hasher.update(h.dataset_hash.bytes(), 32);
        Hash256 training_hash = hasher.finalize();

        if (!meets_target(training_hash, h.nbits)) {
            state.invalid("high-hash");
            return state;
        }
    }

    // ─── Check 11: nbits == expected difficulty ──────────────
    if (h.nbits != ctx.parent_nbits) {
        // Simplified: at retarget boundaries, caller provides expected nbits
        // For non-retarget blocks, nbits must match parent
        state.invalid("bad-diffbits");
        return state;
    }

    // ─── Check 12: dataset_hash == expected ──────────────────
    if (h.dataset_hash != ctx.expected_dataset_hash) {
        state.invalid("bad-dataset-hash");
        return state;
    }

    // ─── Check 13: growth fields match compute_growth ────────
    {
        ModelDimensions expected = compute_growth(h.height, ctx.improving_blocks);
        if (h.d_model != expected.d_model ||
            h.n_layers != expected.n_layers ||
            h.d_ff != expected.d_ff ||
            h.n_experts != expected.n_experts ||
            h.n_heads != expected.n_heads ||
            h.rank != expected.rank) {
            state.invalid("bad-growth");
            return state;
        }
    }

    // ─── Check 14: ed25519_verify(pubkey, header[0..243], sig) ─
    {
        auto unsigned_data = h.unsigned_bytes();
        if (!crypto::verify(h.miner_pubkey,
                            unsigned_data.data(), unsigned_data.size(),
                            h.miner_sig)) {
            state.invalid("bad-signature");
            return state;
        }
    }

    // ─── Check 15: forward eval verification ──────────────────
    // Whitepaper §3, §9: every node independently evaluates the model
    // after applying deltas. Claimed val_loss must match computed val_loss
    // as a raw 32-bit integer (bit-identical, no float comparison ambiguity).
    if (ctx.eval_fn && !block.delta_payload.empty()) {
        float computed_loss = ctx.eval_fn(block.delta_payload);

        uint32_t claimed_bits, computed_bits;
        std::memcpy(&claimed_bits, &h.val_loss, 4);
        std::memcpy(&computed_bits, &computed_loss, 4);

        if (claimed_bits != computed_bits) {
            state.invalid("bad-eval-loss");
            return state;
        }
    }

    return state; // all checks passed
}

} // namespace flow::consensus
