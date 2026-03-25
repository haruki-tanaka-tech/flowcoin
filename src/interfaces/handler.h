// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Event handler interface for managing callback registrations.
// Provides RAII-based disconnect semantics: destroying the handler
// automatically unregisters the callback.

#ifndef FLOWCOIN_INTERFACES_HANDLER_H
#define FLOWCOIN_INTERFACES_HANDLER_H

#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace flow::interfaces {

// ============================================================================
// Handler: manages a single callback registration
// ============================================================================

class Handler {
public:
    virtual ~Handler() = default;

    /// Disconnect the handler (unregister the callback).
    /// After disconnecting, the callback will no longer be invoked.
    /// Safe to call multiple times.
    virtual void disconnect() = 0;

    /// Check if the handler is still connected.
    virtual bool is_connected() const = 0;
};

/// Create a handler that calls cleanup() when disconnected.
/// The cleanup function should unregister the callback from
/// whatever event source it was registered with.
std::unique_ptr<Handler> make_handler(std::function<void()> cleanup);

// ============================================================================
// CleanupHandler: concrete implementation
// ============================================================================

class CleanupHandler : public Handler {
public:
    explicit CleanupHandler(std::function<void()> cleanup);
    ~CleanupHandler() override;

    void disconnect() override;
    bool is_connected() const override;

private:
    std::function<void()> cleanup_;
    std::atomic<bool> connected_{true};
    mutable std::mutex mutex_;
};

// ============================================================================
// HandlerGroup: manages multiple handlers as a unit
// ============================================================================

class HandlerGroup {
public:
    HandlerGroup() = default;
    ~HandlerGroup();

    // Non-copyable
    HandlerGroup(const HandlerGroup&) = delete;
    HandlerGroup& operator=(const HandlerGroup&) = delete;

    // Movable
    HandlerGroup(HandlerGroup&& other) noexcept;
    HandlerGroup& operator=(HandlerGroup&& other) noexcept;

    /// Add a handler to the group.
    void add(std::unique_ptr<Handler> handler);

    /// Disconnect all handlers in the group.
    void disconnect_all();

    /// Get the number of handlers in the group.
    size_t size() const;

    /// Check if any handler is still connected.
    bool any_connected() const;

    /// Remove disconnected handlers.
    void prune();

private:
    std::vector<std::unique_ptr<Handler>> handlers_;
    mutable std::mutex mutex_;
};

// ============================================================================
// SignalConnection: type-safe callback registration with auto-disconnect
// ============================================================================

/// A signal that multiple handlers can connect to.
/// When the signal is emitted, all connected handlers are invoked.
template <typename... Args>
class Signal {
public:
    using Callback = std::function<void(Args...)>;

    Signal() = default;
    ~Signal() { disconnect_all(); }

    // Non-copyable
    Signal(const Signal&) = delete;
    Signal& operator=(const Signal&) = delete;

    /// Connect a callback. Returns a handler that disconnects on destruction.
    std::unique_ptr<Handler> connect(Callback cb) {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t id = next_id_++;

        connections_.push_back({id, std::move(cb)});

        return make_handler([this, id]() {
            std::lock_guard<std::mutex> inner_lock(mutex_);
            connections_.erase(
                std::remove_if(connections_.begin(), connections_.end(),
                    [id](const Connection& c) { return c.id == id; }),
                connections_.end()
            );
        });
    }

    /// Emit the signal, invoking all connected callbacks.
    void emit(Args... args) {
        std::vector<Callback> snapshot;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            snapshot.reserve(connections_.size());
            for (const auto& conn : connections_) {
                snapshot.push_back(conn.callback);
            }
        }

        for (const auto& cb : snapshot) {
            cb(args...);
        }
    }

    /// Disconnect all callbacks.
    void disconnect_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        connections_.clear();
    }

    /// Get the number of connected callbacks.
    size_t connection_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return connections_.size();
    }

private:
    struct Connection {
        uint64_t id;
        Callback callback;
    };

    std::vector<Connection> connections_;
    uint64_t next_id_ = 0;
    mutable std::mutex mutex_;
};

} // namespace flow::interfaces

#endif // FLOWCOIN_INTERFACES_HANDLER_H
