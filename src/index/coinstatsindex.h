// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// UTXO set statistics index: tracks aggregate UTXO set statistics at
// each block height (total count, total value, set hash, disk size,
// unspendable amount). Enables the gettxoutsetinfo RPC to return
// a hash commitment over the entire UTXO set without scanning it.
//
// The UTXO set hash is computed incrementally using XOR of per-UTXO
// hashes: utxo_hash = keccak256d(txid || vout_le4 || amount_le8 || pkh).
// XOR is used because it is commutative and associative, allowing
// incremental updates on block connect/disconnect.

#ifndef FLOWCOIN_INDEX_COINSTATSINDEX_H
#define FLOWCOIN_INDEX_COINSTATSINDEX_H

#include "index/base.h"
#include "primitives/block.h"
#include "util/types.h"

#include <cstdint>
#include <mutex>
#include <string>

struct sqlite3_stmt;

namespace flow {

// ============================================================================
// CoinStats: aggregate UTXO set statistics at a specific block height
// ============================================================================

struct CoinStats {
    uint64_t height = 0;
    uint256  block_hash;
    uint64_t utxo_count = 0;
    Amount   total_amount = 0;
    uint256  utxo_set_hash;        // XOR of all per-UTXO hashes
    size_t   disk_size = 0;        // estimated on-disk size in bytes
    Amount   total_unspendable = 0; // OP_RETURN outputs + provably unspendable
    int64_t  computed_at = 0;       // Unix timestamp when stats were computed

    /// Check if this is a null/empty stats entry.
    bool is_null() const { return height == 0 && block_hash.is_null(); }

    /// Estimated serialized size for storage.
    size_t serialized_size() const;

    /// Serialize to bytes.
    std::vector<uint8_t> serialize() const;

    /// Deserialize from bytes.
    bool deserialize(const uint8_t* data, size_t len);
    bool deserialize(const std::vector<uint8_t>& data) {
        return deserialize(data.data(), data.size());
    }
};

// ============================================================================
// CoinStatsIndex: chain index that tracks UTXO set statistics
// ============================================================================

class CoinStatsIndex : public BaseIndex {
public:
    explicit CoinStatsIndex(const std::string& db_path);
    ~CoinStatsIndex() override;

    // ---- Lookup ------------------------------------------------------------

    /// Get stats at a specific height. Returns false if not available.
    bool get_stats(uint64_t height, CoinStats& stats) const;

    /// Get the latest computed stats.
    CoinStats get_latest() const;

    /// Get stats at the block with the given hash.
    bool get_stats_by_hash(const uint256& block_hash, CoinStats& stats) const;

    /// Get the UTXO set hash at a specific height.
    bool get_utxo_hash(uint64_t height, uint256& hash_out) const;

    /// Get total UTXO count at a specific height.
    bool get_utxo_count(uint64_t height, uint64_t& count_out) const;

    /// Get total amount at a specific height.
    bool get_total_amount(uint64_t height, Amount& amount_out) const;

protected:
    bool write_block(const CBlock& block, uint64_t height) override;
    bool undo_block(const CBlock& block, uint64_t height) override;
    bool init_db() override;

private:
    // Running stats for incremental computation
    CoinStats running_stats_;
    mutable std::mutex stats_mutex_;

    // Prepared statements
    sqlite3_stmt* stmt_insert_ = nullptr;
    sqlite3_stmt* stmt_find_ = nullptr;
    sqlite3_stmt* stmt_find_by_hash_ = nullptr;
    sqlite3_stmt* stmt_delete_ = nullptr;
    sqlite3_stmt* stmt_latest_ = nullptr;

    void prepare_statements();
    void finalize_statements();

    /// Compute the per-UTXO hash for XOR accumulation.
    /// hash = keccak256d(txid || vout_le4 || amount_le8 || pubkey_hash)
    uint256 compute_utxo_hash(const uint256& txid, uint32_t vout,
                               Amount value,
                               const std::array<uint8_t, 32>& pubkey_hash) const;

    /// XOR two uint256 values.
    static uint256 xor_hashes(const uint256& a, const uint256& b);

    /// Load the most recent running stats from the database.
    bool load_running_stats();

    /// Get the current Unix timestamp.
    static int64_t now_seconds();
};

} // namespace flow

#endif // FLOWCOIN_INDEX_COINSTATSINDEX_H
