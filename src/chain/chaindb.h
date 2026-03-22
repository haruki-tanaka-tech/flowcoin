// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Chain database: persists block index to SQLite.
// Survives restarts — node loads full chain on startup.

#pragma once

#include "blockindex.h"
#include <string>
#include <vector>

struct sqlite3;

namespace flow {

class ChainDb {
public:
    explicit ChainDb(const std::string& db_path);
    ~ChainDb();

    ChainDb(const ChainDb&) = delete;
    ChainDb& operator=(const ChainDb&) = delete;

    // Store a block index entry.
    void store_index(const CBlockIndex& idx);

    // Load all block index entries (ordered by height).
    std::vector<CBlockIndex> load_all() const;

    // Get the number of stored blocks.
    size_t count() const;

    // Store best chain tip hash.
    void store_tip(const Hash256& hash);

    // Load best chain tip hash. Returns zero hash if none stored.
    Hash256 load_tip() const;

private:
    sqlite3* db_{nullptr};
    void create_tables();
};

} // namespace flow
