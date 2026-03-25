// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "interfaces/handler.h"

#include <algorithm>
#include <utility>

namespace flow::interfaces {

// ============================================================================
// CleanupHandler
// ============================================================================

CleanupHandler::CleanupHandler(std::function<void()> cleanup)
    : cleanup_(std::move(cleanup)) {
}

CleanupHandler::~CleanupHandler() {
    disconnect();
}

void CleanupHandler::disconnect() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (connected_) {
        connected_ = false;
        if (cleanup_) {
            cleanup_();
            cleanup_ = nullptr;  // Prevent double-call
        }
    }
}

bool CleanupHandler::is_connected() const {
    return connected_;
}

// ============================================================================
// make_handler
// ============================================================================

std::unique_ptr<Handler> make_handler(std::function<void()> cleanup) {
    return std::make_unique<CleanupHandler>(std::move(cleanup));
}

// ============================================================================
// HandlerGroup
// ============================================================================

HandlerGroup::~HandlerGroup() {
    disconnect_all();
}

HandlerGroup::HandlerGroup(HandlerGroup&& other) noexcept {
    std::lock_guard<std::mutex> lock(other.mutex_);
    handlers_ = std::move(other.handlers_);
}

HandlerGroup& HandlerGroup::operator=(HandlerGroup&& other) noexcept {
    if (this != &other) {
        disconnect_all();
        std::lock_guard<std::mutex> lock(other.mutex_);
        handlers_ = std::move(other.handlers_);
    }
    return *this;
}

void HandlerGroup::add(std::unique_ptr<Handler> handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_.push_back(std::move(handler));
}

void HandlerGroup::disconnect_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& handler : handlers_) {
        if (handler) {
            handler->disconnect();
        }
    }
    handlers_.clear();
}

size_t HandlerGroup::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return handlers_.size();
}

bool HandlerGroup::any_connected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& handler : handlers_) {
        if (handler && handler->is_connected()) {
            return true;
        }
    }
    return false;
}

void HandlerGroup::prune() {
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_.erase(
        std::remove_if(handlers_.begin(), handlers_.end(),
            [](const std::unique_ptr<Handler>& h) {
                return !h || !h->is_connected();
            }),
        handlers_.end()
    );
}

} // namespace flow::interfaces
