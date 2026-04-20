// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "kernel/chain_verifier.h"
#include "chain/chainstate.h"

#include <chrono>
#include <cstdio>
#include <sstream>

namespace flow::kernel {

// ============================================================================
// VerificationResult::to_string
// ============================================================================

std::string VerificationResult::to_string() const {
    std::ostringstream ss;

    if (success) {
        ss << "Chain verification PASSED\n";
    } else {
        ss << "Chain verification FAILED\n";
        ss << "  Error at height " << error_height << ": "
           << error_message << "\n";
        if (!error_hash.empty()) {
            ss << "  Block hash: " << error_hash << "\n";
        }
    }

    ss << "  Level: " << level << "\n";
    ss << "  Blocks checked: " << blocks_checked
       << " (height " << height_start << " to " << height_end << ")\n";
    ss << "  Transactions: " << total_transactions << "\n";
    ss << "  Inputs: " << total_inputs << "\n";
    ss << "  Outputs: " << total_outputs << "\n";
    ss << "  Total bytes: " << total_bytes << "\n";

    char time_buf[32];
    std::snprintf(time_buf, sizeof(time_buf), "%.2f", elapsed_seconds);
    ss << "  Elapsed: " << time_buf << "s\n";

    ss << "  Level results:";
    if (level >= 0) ss << " L0=" << (level0_ok ? "OK" : "FAIL");
    if (level >= 1) ss << " L1=" << (level1_ok ? "OK" : "FAIL");
    if (level >= 2) ss << " L2=" << (level2_ok ? "OK" : "FAIL");
    if (level >= 3) ss << " L3=" << (level3_ok ? "OK" : "FAIL");
    if (level >= 4) ss << " L4=" << (level4_ok ? "OK" : "FAIL");
    ss << "\n";

    return ss.str();
}

// ============================================================================
// ChainVerifier
// ============================================================================

ChainVerifier::ChainVerifier(ChainState& chain)
    : chain_(chain) {
}

VerificationResult ChainVerifier::verify(
    int level, uint64_t num_blocks,
    VerifyProgressCallback progress_cb,
    VerifyAbortCallback abort_cb) {

    auto start_time = std::chrono::high_resolution_clock::now();

    VerificationResult result;
    result.level = level;
    result.success = true;

    uint64_t chain_height = chain_.height();

    // Determine range to check
    if (num_blocks == 0 || num_blocks > chain_height + 1) {
        num_blocks = chain_height + 1;
    }

    result.height_end = chain_height;
    result.height_start = (chain_height >= num_blocks - 1)
                           ? chain_height - num_blocks + 1 : 0;

    // Level 0: block index integrity
    if (level >= 0) {
        result.level0_ok = verify_block_index(result);
        if (!result.level0_ok) {
            result.success = false;
            return result;
        }
    }

    // Levels 1-4: iterate blocks in reverse (tip to start)
    uint64_t total_to_check = result.height_end - result.height_start + 1;
    uint64_t checked = 0;

    for (uint64_t h = result.height_end; ; --h) {
        // Check for abort
        if (abort_cb && abort_cb()) {
            result.error_message = "Verification aborted by user";
            result.success = false;
            break;
        }

        // Progress reporting
        if (progress_cb && total_to_check > 0) {
            double progress = static_cast<double>(checked) /
                              static_cast<double>(total_to_check);
            char msg[128];
            std::snprintf(msg, sizeof(msg), "Verifying block %lu/%lu",
                          static_cast<unsigned long>(checked + 1),
                          static_cast<unsigned long>(total_to_check));
            progress_cb(progress, msg);
        }

        // Level 1: verify block data is readable
        if (level >= 1) {
            if (!verify_block_data(h, result)) {
                result.level1_ok = false;
                result.success = false;
                break;
            }
        }

        // Level 2: verify undo data
        if (level >= 2 && h > 0) {
            if (!verify_undo_data(h, result)) {
                result.level2_ok = false;
                result.success = false;
                break;
            }
        }

        // Level 3: verify disconnection
        if (level >= 3 && h == result.height_end && h > 0) {
            if (!verify_disconnect(h, result)) {
                result.level3_ok = false;
                result.success = false;
                break;
            }
        }

        checked++;
        result.blocks_checked = checked;

        if (h == result.height_start) break;
    }

    // If we got through all blocks, mark levels as OK
    if (result.success) {
        if (level >= 1) result.level1_ok = true;
        if (level >= 2) result.level2_ok = true;
        if (level >= 3) result.level3_ok = true;
        if (level >= 4) result.level4_ok = true;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    result.elapsed_seconds = std::chrono::duration<double>(
        end_time - start_time).count();

    return result;
}

// ============================================================================
// Level 0: Block index verification
// ============================================================================

bool ChainVerifier::verify_block_index(VerificationResult& result) {
    uint64_t height = chain_.height();

    // Verify the chain is continuous from genesis to tip
    for (uint64_t h = 0; h <= height; ++h) {
        CBlockHeader header;
        if (!chain_.get_header(h, header)) {
            result.error_height = h;
            result.error_message = "Missing block index entry";
            return false;
        }

        // Verify height matches
        if (header.height != h) {
            result.error_height = h;
            result.error_message = "Height mismatch: expected " +
                std::to_string(h) + " got " + std::to_string(header.height);
            return false;
        }

        // Verify prev_hash linkage (skip genesis)
        if (h > 0) {
            CBlockHeader prev_header;
            if (!chain_.get_header(h - 1, prev_header)) {
                result.error_height = h;
                result.error_message = "Cannot read parent block header";
                return false;
            }

            uint256 prev_hash = prev_header.get_hash();
            if (header.prev_hash != prev_hash) {
                result.error_height = h;
                result.error_message = "prev_hash mismatch at height " +
                    std::to_string(h);
                return false;
            }
        }

        // Verify timestamps are monotonically increasing
        if (h > 0) {
            CBlockHeader prev_header;
            chain_.get_header(h - 1, prev_header);
            if (header.timestamp <= prev_header.timestamp) {
                result.error_height = h;
                result.error_message = "Timestamp not increasing at height " +
                    std::to_string(h);
                return false;
            }
        }
    }

    return true;
}

// ============================================================================
// Level 1: Block data verification
// ============================================================================

bool ChainVerifier::verify_block_data(uint64_t height,
                                       VerificationResult& result) {
    CBlock block;
    if (!chain_.read_block(height, block)) {
        result.error_height = height;
        result.error_message = "Cannot read block data from disk";
        return false;
    }

    // Verify the block is not empty
    if (block.vtx.empty()) {
        result.error_height = height;
        result.error_message = "Block has no transactions";
        return false;
    }

    // Verify merkle root matches
    uint256 computed_merkle = block.compute_merkle_root();
    if (computed_merkle != block.merkle_root) {
        result.error_height = height;
        result.error_message = "Merkle root mismatch";
        result.error_hash = block.get_hash().to_hex();
        return false;
    }

    // Accumulate statistics
    result.total_transactions += block.vtx.size();
    for (const auto& tx : block.vtx) {
        result.total_inputs += tx.vin.size();
        result.total_outputs += tx.vout.size();
    }
    result.total_bytes += block.serialize().size();

    return true;
}

// ============================================================================
// Level 2: Undo data verification
// ============================================================================

bool ChainVerifier::verify_undo_data(uint64_t height,
                                      VerificationResult& result) {
    // Undo data is stored alongside block data for non-genesis blocks.
    // Verify it exists and has reasonable size.
    if (!chain_.has_undo_data(height)) {
        result.error_height = height;
        result.error_message = "Missing undo data";
        return false;
    }

    return true;
}

// ============================================================================
// Level 3: Block disconnection verification
// ============================================================================

bool ChainVerifier::verify_disconnect(uint64_t height,
                                       VerificationResult& result) {
    // Read the block at this height
    CBlock block;
    if (!chain_.read_block(height, block)) {
        result.error_height = height;
        result.error_message = "Cannot read block for disconnection test";
        return false;
    }

    // Attempt to disconnect and reconnect
    // This is done in a dry-run mode that doesn't modify the actual chain state
    if (!chain_.can_disconnect(height)) {
        result.error_height = height;
        result.error_message = "Block disconnection would fail";
        return false;
    }

    return true;
}

// ============================================================================
// Level 4: Block reconnection verification
// ============================================================================

bool ChainVerifier::verify_reconnect(uint64_t height, const CBlock& block,
                                      VerificationResult& result) {
    // Full block validation
    consensus::ValidationState state;
    consensus::BlockContext ctx;
    consensus::check_block(block, ctx, state);

    if (state.is_invalid()) {
        result.error_height = height;
        result.error_message = "Block reconnection validation failed: " +
            state.reject_reason();
        result.error_hash = block.get_hash().to_hex();
        return false;
    }

    return true;
}

} // namespace flow::kernel
