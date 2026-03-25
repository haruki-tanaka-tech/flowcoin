// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Chain integrity verifier.
// Provides comprehensive checks of the blockchain database to detect
// corruption, inconsistencies, or missing data. Used at startup
// (with -checkblocks/-checklevel) and on demand via the `verifychain`
// RPC command.
//
// Verification levels:
//   Level 0: Check block index integrity (in-memory tree)
//   Level 1: Level 0 + verify block data can be read from disk
//   Level 2: Level 1 + verify undo data exists for each block
//   Level 3: Level 2 + verify block disconnection (apply undo)
//   Level 4: Level 3 + verify block reconnection (full validation)

#ifndef FLOWCOIN_KERNEL_CHAIN_VERIFIER_H
#define FLOWCOIN_KERNEL_CHAIN_VERIFIER_H

#include "consensus/validation.h"
#include "primitives/block.h"
#include "util/types.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace flow {
class ChainState;
}

namespace flow::kernel {

// ============================================================================
// Verification result
// ============================================================================

struct VerificationResult {
    bool success = false;
    int level = 0;                // Verification level completed
    uint64_t blocks_checked = 0;  // Number of blocks verified
    uint64_t height_start = 0;    // First block checked
    uint64_t height_end = 0;      // Last block checked

    // Error details (if any)
    uint64_t error_height = 0;
    std::string error_message;
    std::string error_hash;

    // Statistics
    uint64_t total_transactions = 0;
    uint64_t total_inputs = 0;
    uint64_t total_outputs = 0;
    uint64_t total_sigops = 0;
    uint64_t total_bytes = 0;
    double elapsed_seconds = 0.0;

    // Per-level pass/fail
    bool level0_ok = false;  // Block index
    bool level1_ok = false;  // Block data readable
    bool level2_ok = false;  // Undo data exists
    bool level3_ok = false;  // Disconnection works
    bool level4_ok = false;  // Reconnection works

    std::string to_string() const;
};

// ============================================================================
// Progress callback
// ============================================================================

/// Called periodically during verification with progress [0.0, 1.0].
using VerifyProgressCallback = std::function<void(double progress,
                                                   const std::string& message)>;

/// Called to check if verification should be aborted.
using VerifyAbortCallback = std::function<bool()>;

// ============================================================================
// ChainVerifier
// ============================================================================

class ChainVerifier {
public:
    /// Construct a verifier for the given chain state.
    explicit ChainVerifier(ChainState& chain);

    /// Run verification at the specified level, checking the last N blocks.
    ///
    /// @param level        Verification depth (0-4).
    /// @param num_blocks   Number of blocks from the tip to check.
    ///                     0 = all blocks.
    /// @param progress_cb  Optional progress callback.
    /// @param abort_cb     Optional abort callback.
    /// @return             Verification result.
    VerificationResult verify(int level, uint64_t num_blocks = 6,
                               VerifyProgressCallback progress_cb = nullptr,
                               VerifyAbortCallback abort_cb = nullptr);

private:
    ChainState& chain_;

    // Level 0: Verify block index tree integrity
    bool verify_block_index(VerificationResult& result);

    // Level 1: Verify block data is readable from disk
    bool verify_block_data(uint64_t height, VerificationResult& result);

    // Level 2: Verify undo data exists
    bool verify_undo_data(uint64_t height, VerificationResult& result);

    // Level 3: Verify block disconnection
    bool verify_disconnect(uint64_t height, VerificationResult& result);

    // Level 4: Verify block reconnection
    bool verify_reconnect(uint64_t height, const CBlock& block,
                           VerificationResult& result);
};

} // namespace flow::kernel

#endif // FLOWCOIN_KERNEL_CHAIN_VERIFIER_H
