// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// RunContext: shutdown coordination for the FlowCoin process.
// Provides a thread-safe mechanism for any module to request a clean
// shutdown (via request_shutdown()) and for the main loop to check
// whether shutdown has been requested (via shutdown_requested()).
//
// Also tracks the application's run state (starting, running, shutting
// down, stopped) and provides hooks for modules to register cleanup
// callbacks that execute during shutdown.

#ifndef FLOWCOIN_COMMON_RUN_CONTEXT_H
#define FLOWCOIN_COMMON_RUN_CONTEXT_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace flow::common {

// ============================================================================
// Application run state
// ============================================================================

enum class RunState : int {
    STARTING = 0,     // Initialization in progress
    RUNNING = 1,      // Fully operational
    SHUTTING_DOWN = 2, // Shutdown requested, cleanup in progress
    STOPPED = 3,      // All modules stopped
};

// ============================================================================
// Shutdown callback
// ============================================================================

struct ShutdownCallback {
    std::string name;         // Module name for logging
    int priority;             // Lower priority = called first (0 = first)
    std::function<void()> fn; // Cleanup function
};

// ============================================================================
// RunContext
// ============================================================================

class RunContext {
public:
    RunContext() = default;

    // ---- State queries ----------------------------------------------------

    /// Check if shutdown has been requested.
    bool shutdown_requested() const {
        return state_.load(std::memory_order_acquire) >= static_cast<int>(RunState::SHUTTING_DOWN);
    }

    /// Get the current run state.
    RunState state() const {
        return static_cast<RunState>(state_.load(std::memory_order_acquire));
    }

    /// Check if the application is fully running.
    bool is_running() const {
        return state_.load(std::memory_order_acquire) == static_cast<int>(RunState::RUNNING);
    }

    // ---- State transitions -------------------------------------------------

    /// Mark the application as fully started and running.
    void set_running() {
        state_.store(static_cast<int>(RunState::RUNNING), std::memory_order_release);
        cv_.notify_all();
    }

    /// Request a shutdown. Safe to call from any thread, any number of times.
    void request_shutdown(const std::string& reason = "") {
        int expected = static_cast<int>(RunState::RUNNING);
        if (state_.compare_exchange_strong(expected,
                static_cast<int>(RunState::SHUTTING_DOWN),
                std::memory_order_acq_rel)) {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_reason_ = reason;
            cv_.notify_all();
        }
    }

    /// Mark the application as fully stopped.
    void set_stopped() {
        state_.store(static_cast<int>(RunState::STOPPED), std::memory_order_release);
        cv_.notify_all();
    }

    /// Wait until shutdown is requested. Blocks the calling thread.
    void wait_for_shutdown() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] {
            return state_.load(std::memory_order_acquire) >=
                   static_cast<int>(RunState::SHUTTING_DOWN);
        });
    }

    /// Wait until shutdown is requested, with a timeout.
    /// Returns true if shutdown was requested, false if timeout expired.
    bool wait_for_shutdown(int64_t timeout_ms) {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] {
            return state_.load(std::memory_order_acquire) >=
                   static_cast<int>(RunState::SHUTTING_DOWN);
        });
    }

    /// Get the reason for shutdown (if any).
    std::string get_shutdown_reason() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return shutdown_reason_;
    }

    // ---- Shutdown callbacks ------------------------------------------------

    /// Register a cleanup callback to be called during shutdown.
    /// Lower priority values are called first.
    void register_shutdown_callback(const std::string& name,
                                     int priority,
                                     std::function<void()> fn) {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.push_back({name, priority, std::move(fn)});
    }

    /// Execute all registered shutdown callbacks in priority order.
    /// Called once during shutdown. Safe to call multiple times (idempotent).
    void execute_shutdown_callbacks() {
        std::vector<ShutdownCallback> cbs;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (callbacks_executed_) return;
            callbacks_executed_ = true;
            cbs = callbacks_;
        }

        // Sort by priority (ascending)
        std::sort(cbs.begin(), cbs.end(),
            [](const ShutdownCallback& a, const ShutdownCallback& b) {
                return a.priority < b.priority;
            });

        for (const auto& cb : cbs) {
            try {
                cb.fn();
            } catch (...) {
                // Swallow exceptions during shutdown cleanup
            }
        }
    }

    // ---- Global instance ---------------------------------------------------

    static RunContext& instance() {
        static RunContext ctx;
        return ctx;
    }

private:
    std::atomic<int> state_{static_cast<int>(RunState::STARTING)};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::string shutdown_reason_;
    std::vector<ShutdownCallback> callbacks_;
    bool callbacks_executed_ = false;
};

// ============================================================================
// Convenience free functions
// ============================================================================

inline bool shutdown_requested() {
    return RunContext::instance().shutdown_requested();
}

inline void request_shutdown(const std::string& reason = "") {
    RunContext::instance().request_shutdown(reason);
}

} // namespace flow::common

#endif // FLOWCOIN_COMMON_RUN_CONTEXT_H
