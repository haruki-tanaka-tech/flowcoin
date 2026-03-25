// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "kernel/notifications.h"

#include <cstdio>
#include <cstring>

namespace flow::kernel {

// ============================================================================
// LoggingNotifications implementation
// ============================================================================

void LoggingNotifications::block_connected(const CBlock& block,
                                            uint64_t height) {
    uint256 hash = block.get_hash();
    std::fprintf(stdout, "[kernel] Block connected: height=%lu hash=%s txs=%zu\n",
                 static_cast<unsigned long>(height),
                 hash.to_hex().substr(0, 16).c_str(),
                 block.vtx.size());
}

void LoggingNotifications::block_disconnected(const CBlock& block,
                                               uint64_t height) {
    uint256 hash = block.get_hash();
    std::fprintf(stdout, "[kernel] Block disconnected: height=%lu hash=%s\n",
                 static_cast<unsigned long>(height),
                 hash.to_hex().substr(0, 16).c_str());
}

void LoggingNotifications::updated_block_tip(uint64_t height,
                                              const uint256& hash,
                                              bool initial_download) {
    std::fprintf(stdout, "[kernel] New tip: height=%lu hash=%s%s\n",
                 static_cast<unsigned long>(height),
                 hash.to_hex().substr(0, 16).c_str(),
                 initial_download ? " (IBD)" : "");
}

void LoggingNotifications::header_invalid(
    const CBlockHeader& header,
    const consensus::ValidationState& state) {
    std::fprintf(stderr, "[kernel] Invalid header at height %lu: %s (%s)\n",
                 static_cast<unsigned long>(header.height),
                 state.reject_reason().c_str(),
                 state.debug_message().c_str());
}

void LoggingNotifications::block_invalid(
    const CBlock& block,
    const consensus::ValidationState& state) {
    std::fprintf(stderr, "[kernel] Invalid block at height %lu: %s (%s)\n",
                 static_cast<unsigned long>(block.height),
                 state.reject_reason().c_str(),
                 state.debug_message().c_str());
}

void LoggingNotifications::progress(ProgressPhase phase, double progress,
                                     const std::string& message) {
    const char* phase_name = "unknown";
    switch (phase) {
        case ProgressPhase::HEADER_SYNC: phase_name = "Header sync"; break;
        case ProgressPhase::BLOCK_SYNC:  phase_name = "Block sync"; break;
        case ProgressPhase::UTXO_REBUILD: phase_name = "UTXO rebuild"; break;
        case ProgressPhase::INDEX_SYNC:  phase_name = "Index sync"; break;
        case ProgressPhase::MODEL_SYNC:  phase_name = "Model sync"; break;
        case ProgressPhase::VERIFICATION: phase_name = "Verification"; break;
        case ProgressPhase::READY:       phase_name = "Ready"; break;
    }

    std::fprintf(stdout, "[kernel] %s: %.1f%% %s\n",
                 phase_name, progress * 100.0, message.c_str());
}

void LoggingNotifications::warning(WarningType type,
                                    const std::string& message) {
    const char* severity = "INFO";
    switch (type) {
        case WarningType::INFO:     severity = "INFO"; break;
        case WarningType::CAUTION:  severity = "CAUTION"; break;
        case WarningType::WARNING:  severity = "WARNING"; break;
        case WarningType::CRITICAL: severity = "CRITICAL"; break;
    }

    auto stream = (type >= WarningType::WARNING) ? stderr : stdout;
    std::fprintf(stream, "[kernel] %s: %s\n", severity, message.c_str());
}

void LoggingNotifications::fatal_error(const std::string& message) {
    std::fprintf(stderr, "[kernel] FATAL: %s\n", message.c_str());
    shutdown_ = true;
}

bool LoggingNotifications::shutdown_requested() {
    return shutdown_;
}

} // namespace flow::kernel
