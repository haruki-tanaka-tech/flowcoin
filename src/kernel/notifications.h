// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Kernel notification interface.
// The kernel uses this interface to notify the application layer about
// consensus events (block connected/disconnected, validation errors,
// progress updates) without depending on specific application code.
//
// The application provides an implementation of KernelNotifications
// to the kernel at initialization time. The kernel calls these methods
// at the appropriate points during block processing.
//
// This is the primary mechanism for separation between the consensus
// engine (libflowcoinkernel) and the node application.

#ifndef FLOWCOIN_KERNEL_NOTIFICATIONS_H
#define FLOWCOIN_KERNEL_NOTIFICATIONS_H

#include "consensus/validation.h"
#include "primitives/block.h"
#include "util/types.h"

#include <cstdint>
#include <string>

namespace flow::kernel {

// ============================================================================
// Warning severity levels
// ============================================================================

enum class WarningType : int {
    INFO = 0,      // Informational (not a problem)
    CAUTION = 1,   // Potential issue (e.g., clock skew)
    WARNING = 2,   // Significant issue (e.g., old software version)
    CRITICAL = 3,  // Critical issue (e.g., invalid chain tip)
};

// ============================================================================
// Progress reporting
// ============================================================================

enum class ProgressPhase : int {
    HEADER_SYNC = 0,   // Downloading headers
    BLOCK_SYNC = 1,    // Downloading and validating blocks
    UTXO_REBUILD = 2,  // Rebuilding UTXO set from blocks
    INDEX_SYNC = 3,    // Building optional indexes
    MODEL_SYNC = 4,    // Replaying model training from deltas
    VERIFICATION = 5,  // Verifying chain integrity
    READY = 6,         // Fully synced and operational
};

// ============================================================================
// KernelNotifications interface
// ============================================================================

class KernelNotifications {
public:
    virtual ~KernelNotifications() = default;

    // ---- Block events ------------------------------------------------------

    /// Called when a new block has been connected to the active chain.
    /// The block has been fully validated and the UTXO set has been updated.
    virtual void block_connected(const CBlock& block, uint64_t height) = 0;

    /// Called when a block has been disconnected from the active chain
    /// during a reorganization.
    virtual void block_disconnected(const CBlock& block, uint64_t height) = 0;

    /// Called when a new best chain tip has been selected.
    /// This may be called without block_connected if the tip changes
    /// due to header-only sync.
    virtual void updated_block_tip(uint64_t height, const uint256& hash,
                                    bool initial_download) = 0;

    // ---- Validation events -------------------------------------------------

    /// Called when a header fails validation.
    virtual void header_invalid(const CBlockHeader& header,
                                 const consensus::ValidationState& state) = 0;

    /// Called when a block fails validation.
    virtual void block_invalid(const CBlock& block,
                                const consensus::ValidationState& state) = 0;

    // ---- Progress ----------------------------------------------------------

    /// Called periodically during long operations to report progress.
    /// @param phase     Current operation phase.
    /// @param progress  Fraction complete (0.0 to 1.0).
    /// @param message   Human-readable progress description.
    virtual void progress(ProgressPhase phase, double progress,
                           const std::string& message) = 0;

    // ---- Warnings ----------------------------------------------------------

    /// Called when the kernel wants to issue a warning.
    virtual void warning(WarningType type, const std::string& message) = 0;

    // ---- Shutdown ----------------------------------------------------------

    /// Called when the kernel encounters a fatal error and must shut down.
    /// The application should initiate a clean shutdown.
    virtual void fatal_error(const std::string& message) = 0;

    /// Called to check if shutdown has been requested by the application.
    /// The kernel checks this periodically during long operations.
    virtual bool shutdown_requested() = 0;
};

// ============================================================================
// Default (no-op) implementation
// ============================================================================

class DefaultNotifications : public KernelNotifications {
public:
    void block_connected(const CBlock&, uint64_t) override {}
    void block_disconnected(const CBlock&, uint64_t) override {}
    void updated_block_tip(uint64_t, const uint256&, bool) override {}
    void header_invalid(const CBlockHeader&,
                         const consensus::ValidationState&) override {}
    void block_invalid(const CBlock&,
                        const consensus::ValidationState&) override {}
    void progress(ProgressPhase, double, const std::string&) override {}
    void warning(WarningType, const std::string&) override {}
    void fatal_error(const std::string&) override {}
    bool shutdown_requested() override { return false; }
};

// ============================================================================
// Logging implementation (prints all events to the log)
// ============================================================================

class LoggingNotifications : public KernelNotifications {
public:
    void block_connected(const CBlock& block, uint64_t height) override;
    void block_disconnected(const CBlock& block, uint64_t height) override;
    void updated_block_tip(uint64_t height, const uint256& hash,
                            bool initial_download) override;
    void header_invalid(const CBlockHeader& header,
                         const consensus::ValidationState& state) override;
    void block_invalid(const CBlock& block,
                        const consensus::ValidationState& state) override;
    void progress(ProgressPhase phase, double progress,
                   const std::string& message) override;
    void warning(WarningType type, const std::string& message) override;
    void fatal_error(const std::string& message) override;
    bool shutdown_requested() override;

    /// Set a flag to indicate that shutdown has been requested.
    void set_shutdown_flag() { shutdown_ = true; }

private:
    bool shutdown_ = false;
};

} // namespace flow::kernel

#endif // FLOWCOIN_KERNEL_NOTIFICATIONS_H
