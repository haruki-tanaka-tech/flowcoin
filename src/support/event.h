// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Lightweight event/signal system for decoupled module communication.
// Modules can subscribe to events and get notified when they fire,
// without the publisher needing to know about subscribers.
//
// Thread-safe: subscriptions and notifications can happen from any thread.
//
// Usage:
//   Event<int, std::string> on_block_connected;
//   auto id = on_block_connected.subscribe([](int h, const std::string& hash) {
//       printf("Block %d (%s) connected\n", h, hash.c_str());
//   });
//   on_block_connected.fire(42, "abc123");
//   on_block_connected.unsubscribe(id);

#ifndef FLOWCOIN_SUPPORT_EVENT_H
#define FLOWCOIN_SUPPORT_EVENT_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

namespace flow {

using EventId = uint64_t;

template<typename... Args>
class Event {
public:
    using Callback = std::function<void(Args...)>;

    Event() = default;

    // Non-copyable (subscriptions are tied to this instance)
    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;

    // Movable
    Event(Event&& other) noexcept {
        std::lock_guard<std::mutex> lock(other.mutex_);
        subscribers_ = std::move(other.subscribers_);
    }

    Event& operator=(Event&& other) noexcept {
        if (this != &other) {
            std::lock_guard<std::mutex> lock1(mutex_);
            std::lock_guard<std::mutex> lock2(other.mutex_);
            subscribers_ = std::move(other.subscribers_);
        }
        return *this;
    }

    /// Subscribe to this event. Returns an ID for later unsubscription.
    EventId subscribe(Callback cb) {
        std::lock_guard<std::mutex> lock(mutex_);
        EventId id = next_id_++;
        subscribers_.push_back({id, std::move(cb), true});
        return id;
    }

    /// Unsubscribe by ID. Returns true if the subscription was found.
    bool unsubscribe(EventId id) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& sub : subscribers_) {
            if (sub.id == id) {
                sub.active = false;
                return true;
            }
        }
        return false;
    }

    /// Fire the event, notifying all active subscribers.
    /// Subscribers are called synchronously in subscription order.
    /// Inactive subscriptions are cleaned up during firing.
    void fire(Args... args) {
        std::vector<Callback> to_call;

        {
            std::lock_guard<std::mutex> lock(mutex_);

            // Collect active callbacks
            to_call.reserve(subscribers_.size());
            for (const auto& sub : subscribers_) {
                if (sub.active) {
                    to_call.push_back(sub.callback);
                }
            }

            // Compact: remove inactive subscriptions
            subscribers_.erase(
                std::remove_if(subscribers_.begin(), subscribers_.end(),
                    [](const Subscription& s) { return !s.active; }),
                subscribers_.end());
        }

        // Call outside the lock to prevent deadlocks
        for (auto& cb : to_call) {
            cb(args...);
        }
    }

    /// Get the number of active subscribers.
    size_t subscriber_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& sub : subscribers_) {
            if (sub.active) ++count;
        }
        return count;
    }

    /// Remove all subscribers.
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        subscribers_.clear();
    }

private:
    struct Subscription {
        EventId id;
        Callback callback;
        bool active;
    };

    mutable std::mutex mutex_;
    std::vector<Subscription> subscribers_;
    static std::atomic<EventId> next_id_;
};

template<typename... Args>
std::atomic<EventId> Event<Args...>::next_id_{1};

// ============================================================================
// RAII subscription handle — automatically unsubscribes on destruction
// ============================================================================

template<typename... Args>
class ScopedSubscription {
public:
    ScopedSubscription() = default;

    ScopedSubscription(Event<Args...>& event,
                        typename Event<Args...>::Callback cb)
        : event_(&event) {
        id_ = event_->subscribe(std::move(cb));
    }

    ~ScopedSubscription() {
        if (event_) {
            event_->unsubscribe(id_);
        }
    }

    // Non-copyable
    ScopedSubscription(const ScopedSubscription&) = delete;
    ScopedSubscription& operator=(const ScopedSubscription&) = delete;

    // Movable
    ScopedSubscription(ScopedSubscription&& other) noexcept
        : event_(other.event_), id_(other.id_) {
        other.event_ = nullptr;
    }

    ScopedSubscription& operator=(ScopedSubscription&& other) noexcept {
        if (this != &other) {
            if (event_) event_->unsubscribe(id_);
            event_ = other.event_;
            id_ = other.id_;
            other.event_ = nullptr;
        }
        return *this;
    }

    /// Get the subscription ID.
    EventId id() const { return id_; }

    /// Release the subscription without unsubscribing.
    EventId release() {
        event_ = nullptr;
        return id_;
    }

private:
    Event<Args...>* event_ = nullptr;
    EventId id_ = 0;
};

// ============================================================================
// Common event types used throughout FlowCoin
// ============================================================================

namespace events {

/// Fired when a new block is connected to the active chain.
/// Args: height, block_hash
using BlockConnected = Event<uint64_t, uint256>;

/// Fired when a block is disconnected from the active chain (reorg).
/// Args: height, block_hash
using BlockDisconnected = Event<uint64_t, uint256>;

/// Fired when a new transaction enters the mempool.
/// Args: txid, fee
using TransactionAdded = Event<uint256, int64_t>;

/// Fired when a transaction is removed from the mempool.
/// Args: txid, reason_string
using TransactionRemoved = Event<uint256, std::string>;

/// Fired when a new peer connects.
/// Args: peer_id, address_string
using PeerConnected = Event<int64_t, std::string>;

/// Fired when a peer disconnects.
/// Args: peer_id, reason_string
using PeerDisconnected = Event<int64_t, std::string>;

/// Fired when the chain tip changes.
/// Args: new_height, new_hash, old_height, old_hash
using ChainTipChanged = Event<uint64_t, uint256, uint64_t, uint256>;

/// Fired when the node enters or exits IBD mode.
/// Args: is_ibd
using IBDStateChanged = Event<bool>;

/// Fired on wallet balance change.
/// Args: wallet_name, new_balance
using WalletBalanceChanged = Event<std::string, int64_t>;

} // namespace events

} // namespace flow

#endif // FLOWCOIN_SUPPORT_EVENT_H
