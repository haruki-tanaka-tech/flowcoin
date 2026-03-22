// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Block validation: 14 checks that ALL must pass.
// Any failure → reject block with specific reason.

#pragma once

#include "core/types.h"
#include "primitives/block.h"
#include <string>

namespace flow::consensus {

// Validation result with specific rejection reason
struct ValidationState {
    bool valid{true};
    std::string reject_reason;

    void invalid(const std::string& reason) {
        valid = false;
        reject_reason = reason;
    }

    explicit operator bool() const { return valid; }
};

// Context about the parent block, needed for contextual checks.
struct BlockContext {
    Hash256  parent_hash;
    uint64_t parent_height{0};
    int64_t  parent_timestamp{0};
    float    parent_val_loss{0.0f};
    uint32_t parent_nbits{0};
    uint32_t parent_d_model{0};
    uint32_t parent_n_layers{0};
    uint32_t parent_d_ff{0};
    uint32_t parent_n_experts{0};
    uint32_t parent_n_heads{0};
    uint32_t parent_rank{0};
    uint32_t improving_blocks{0}; // total improving blocks up to parent
    int64_t  current_time{0};     // current node time
    Hash256  expected_dataset_hash;
};

// Run all 14 validation checks on a block.
// Returns ValidationState with reject_reason if any check fails.
//
//  1. prev_hash == parent.hash
//  2. height == parent.height + 1
//  3. timestamp > parent.timestamp
//  4. timestamp >= parent.timestamp + 300
//  5. timestamp <= now + 7200
//  6. isfinite(val_loss) && val_loss > 0
//  7. val_loss < 1000.0
//  8. prev_val_loss == parent.val_loss (bit-identical)
//  9. val_loss <= 2.0 * parent.val_loss
// 10. training_hash < difficulty_target
// 11. nbits == expected difficulty
// 12. dataset_hash == expected
// 13. growth fields match compute_growth(parent)
// 14. ed25519_verify(pubkey, header[0..243], sig)
ValidationState check_block(const CBlock& block, const BlockContext& ctx);

} // namespace flow::consensus
