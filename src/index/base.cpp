// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "index/base.h"
#include "hash/keccak.h"
#include "util/strencodings.h"

#include <sqlite3.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <stdexcept>

namespace flow {

// ============================================================================
// State name helper
// ============================================================================

const char* index_state_name(BaseIndex::State s) {
    switch (s) {
        case BaseIndex::State::IDLE:    return "IDLE";
        case BaseIndex::State::SYNCING: return "SYNCING";
        case BaseIndex::State::SYNCED:  return "SYNCED";
        case BaseIndex::State::IDX_ERROR:   return "ERROR";
    }
    return "UNKNOWN";
}

// ============================================================================
// Construction / destruction
// ============================================================================

BaseIndex::BaseIndex(const std::string& name, const std::string& db_path)
    : name_(name), db_path_(db_path) {
}

BaseIndex::~BaseIndex() {
    stop();
    finalize_meta_stmts();
    close_db();
}

// ============================================================================
// Database operations
// ============================================================================

bool BaseIndex::open_db() {
    if (db_) return true;

    int rc = sqlite3_open_v2(
        db_path_.c_str(), &db_,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );
    if (rc != SQLITE_OK) {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return false;
    }

    // Enable WAL mode for concurrent reads during sync
    exec_sql("PRAGMA journal_mode=WAL");
    exec_sql("PRAGMA synchronous=NORMAL");
    exec_sql("PRAGMA cache_size=-8192");  // 8 MB cache
    exec_sql("PRAGMA temp_store=MEMORY");
    exec_sql("PRAGMA mmap_size=268435456");  // 256 MB mmap

    return true;
}

void BaseIndex::close_db() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool BaseIndex::exec_sql(const char* sql) {
    if (!db_) return false;
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        if (err_msg) {
            sqlite3_free(err_msg);
        }
        return false;
    }
    return true;
}

// ============================================================================
// Meta table
// ============================================================================

bool BaseIndex::create_meta_table() {
    const char* sql =
        "CREATE TABLE IF NOT EXISTS index_meta ("
        "  key TEXT PRIMARY KEY,"
        "  value BLOB NOT NULL"
        ")";
    return exec_sql(sql);
}

void BaseIndex::prepare_meta_stmts() {
    if (!db_) return;

    const char* save_sql =
        "INSERT OR REPLACE INTO index_meta (key, value) VALUES ('best_height', ?)";
    sqlite3_prepare_v2(db_, save_sql, -1, &stmt_save_height_, nullptr);

    const char* load_sql =
        "SELECT value FROM index_meta WHERE key = 'best_height'";
    sqlite3_prepare_v2(db_, load_sql, -1, &stmt_load_height_, nullptr);
}

void BaseIndex::finalize_meta_stmts() {
    if (stmt_save_height_) {
        sqlite3_finalize(stmt_save_height_);
        stmt_save_height_ = nullptr;
    }
    if (stmt_load_height_) {
        sqlite3_finalize(stmt_load_height_);
        stmt_load_height_ = nullptr;
    }
}

bool BaseIndex::save_best_height(uint64_t height) {
    if (!stmt_save_height_) return false;

    sqlite3_reset(stmt_save_height_);
    sqlite3_bind_int64(stmt_save_height_, 1, static_cast<int64_t>(height));
    int rc = sqlite3_step(stmt_save_height_);
    return rc == SQLITE_DONE;
}

uint64_t BaseIndex::load_best_height() const {
    if (!stmt_load_height_) return 0;

    sqlite3_reset(stmt_load_height_);
    int rc = sqlite3_step(stmt_load_height_);
    if (rc == SQLITE_ROW) {
        return static_cast<uint64_t>(sqlite3_column_int64(stmt_load_height_, 0));
    }
    return 0;
}

// ============================================================================
// Lifecycle
// ============================================================================

bool BaseIndex::start() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != State::IDLE && state_ != State::IDX_ERROR) {
        return false;  // Already running
    }

    // Open the database
    if (!open_db()) {
        state_ = State::IDX_ERROR;
        return false;
    }

    // Create meta table
    if (!create_meta_table()) {
        state_ = State::IDX_ERROR;
        return false;
    }

    // Prepare meta statements
    prepare_meta_stmts();

    // Load previous best height
    best_height_ = load_best_height();

    // Initialize index-specific tables
    if (!init_db()) {
        state_ = State::IDX_ERROR;
        return false;
    }

    // Start background thread
    shutdown_ = false;
    state_ = State::SYNCING;

    worker_ = std::thread([this]() { thread_main(); });

    return true;
}

void BaseIndex::stop() {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        shutdown_ = true;
    }
    queue_cv_.notify_one();

    if (worker_.joinable()) {
        worker_.join();
    }

    // Commit any pending batch
    if (in_batch_) {
        commit_batch();
    }

    // Save final height
    {
        std::lock_guard<std::mutex> lock(mutex_);
        save_best_height(best_height_);
    }

    state_ = State::IDLE;
}

bool BaseIndex::is_synced() const {
    return state_ == State::SYNCED;
}

BaseIndex::State BaseIndex::state() const {
    return state_;
}

// ============================================================================
// Sync progress
// ============================================================================

uint64_t BaseIndex::best_height() const {
    return best_height_;
}

double BaseIndex::sync_progress() const {
    uint64_t chain = chain_height_;
    if (chain == 0) return 1.0;
    uint64_t best = best_height_;
    if (best >= chain) return 1.0;
    return static_cast<double>(best) / static_cast<double>(chain);
}

void BaseIndex::set_chain_height(uint64_t height) {
    chain_height_ = height;
}

// ============================================================================
// Chain notifications
// ============================================================================

void BaseIndex::block_connected(const CBlock& block, uint64_t height) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        queue_.push_back({block, height, true});
    }
    queue_cv_.notify_one();
    chain_height_ = std::max(chain_height_.load(), height);
}

void BaseIndex::block_disconnected(const CBlock& block, uint64_t height) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        queue_.push_back({block, height, false});
    }
    queue_cv_.notify_one();
}

// ============================================================================
// Batch processing
// ============================================================================

void BaseIndex::begin_batch() {
    if (!in_batch_ && db_) {
        exec_sql("BEGIN TRANSACTION");
        in_batch_ = true;
        batch_count_ = 0;
    }
}

void BaseIndex::commit_batch() {
    if (in_batch_ && db_) {
        save_best_height(best_height_);
        exec_sql("COMMIT");
        in_batch_ = false;
        batch_count_ = 0;
    }
}

void BaseIndex::rollback_batch() {
    if (in_batch_ && db_) {
        exec_sql("ROLLBACK");
        in_batch_ = false;
        batch_count_ = 0;
    }
}

// ============================================================================
// Background thread
// ============================================================================

void BaseIndex::thread_main() {
    while (!shutdown_) {
        std::deque<BlockEvent> local_queue;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait_for(lock, std::chrono::milliseconds(100), [this]() {
                return !queue_.empty() || shutdown_.load();
            });

            if (shutdown_ && queue_.empty()) break;

            local_queue.swap(queue_);
        }

        if (local_queue.empty()) {
            // No work -- check if we are synced
            uint64_t best = best_height_;
            uint64_t chain = chain_height_;
            if (best >= chain && chain > 0) {
                state_ = State::SYNCED;
            }
            continue;
        }

        // Process events in batch
        begin_batch();
        for (const auto& event : local_queue) {
            if (!process_event(event)) {
                rollback_batch();
                state_ = State::IDX_ERROR;
                return;
            }
            batch_count_++;
            if (batch_count_ >= BATCH_SIZE) {
                commit_batch();
                begin_batch();
            }
        }
        commit_batch();

        // Check sync status
        uint64_t best = best_height_;
        uint64_t chain = chain_height_;
        if (best >= chain && chain > 0) {
            state_ = State::SYNCED;
        } else {
            state_ = State::SYNCING;
        }
    }

    // Drain remaining queue on shutdown
    std::deque<BlockEvent> remaining;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        remaining.swap(queue_);
    }
    if (!remaining.empty()) {
        begin_batch();
        for (const auto& event : remaining) {
            process_event(event);
        }
        commit_batch();
    }
}

void BaseIndex::process_queue() {
    std::deque<BlockEvent> local_queue;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        local_queue.swap(queue_);
    }

    for (const auto& event : local_queue) {
        process_event(event);
    }
}

bool BaseIndex::process_event(const BlockEvent& event) {
    if (event.connected) {
        // Ensure sequential processing -- skip if we already processed this height
        uint64_t best = best_height_;
        if (event.height <= best) {
            return true;  // Already processed, skip
        }

        if (!write_block(event.block, event.height)) {
            return false;
        }
        best_height_ = event.height;
    } else {
        // Disconnect: only undo if this is our current best height
        uint64_t best = best_height_;
        if (event.height != best) {
            return true;  // Not our tip, skip
        }

        if (!undo_block(event.block, event.height)) {
            return false;
        }
        if (best > 0) {
            best_height_ = best - 1;
        }
    }
    return true;
}

} // namespace flow
