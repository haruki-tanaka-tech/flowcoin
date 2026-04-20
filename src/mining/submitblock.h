// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Block submission: accepts a complete block from a miner or from the
// network and validates it against the chain state. Handles the full
// pipeline from raw bytes to chain acceptance, including relay to peers
// and mempool updates.

#ifndef FLOWCOIN_MINING_SUBMITBLOCK_H
#define FLOWCOIN_MINING_SUBMITBLOCK_H

#include "primitives/block.h"
#include "util/types.h"

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

class ChainState;
class NetManager;
class Mempool;

// ---------------------------------------------------------------------------
// SubmitResult -- outcome of a block submission
// ---------------------------------------------------------------------------

struct SubmitResult {
    bool accepted;                     //!< Was the block accepted into the chain?
    std::string reject_reason;         //!< Reason for rejection (empty if accepted)
    uint256 block_hash;                //!< Hash of the submitted block
    uint64_t height;                   //!< Height of the submitted block
    int64_t processing_time_us;        //!< Time spent processing (microseconds)

    /// Check if the block was accepted.
    bool ok() const { return accepted; }

    /// Get a human-readable description of the result.
    std::string to_string() const;
};

// ---------------------------------------------------------------------------
// BlockSubmitter -- handles block submission and relay
// ---------------------------------------------------------------------------

class BlockSubmitter {
public:
    /// Construct with required references.
    /// NetManager and Mempool are optional (null = no relay / no mempool update).
    BlockSubmitter(ChainState& chain, NetManager* net = nullptr, Mempool* mempool = nullptr);

    /// Submit a fully assembled block from a local miner.
    SubmitResult submit(const CBlock& block);

    /// Submit a block from a hex-encoded string (for submitblock RPC).
    SubmitResult submit_hex(const std::string& hex_block);

    /// Submit a block from raw bytes (for wire protocol).
    SubmitResult submit_raw(const std::vector<uint8_t>& raw_block);

    /// Process a block received from a network peer.
    /// Performs additional checks for rate limiting and duplicate detection.
    SubmitResult process_network_block(const CBlock& block, uint64_t peer_id);

    // --- Configuration ---

    /// Set the minimum interval between blocks from the same peer (seconds).
    /// Blocks arriving faster than this from the same peer are rate-limited.
    void set_min_peer_block_interval(int64_t seconds) {
        min_peer_block_interval_ = seconds;
    }

    /// Enable/disable relaying accepted blocks to peers.
    void set_relay_enabled(bool enabled) { relay_enabled_ = enabled; }

    /// Enable/disable mempool updates after block acceptance.
    void set_mempool_update_enabled(bool enabled) { mempool_update_enabled_ = enabled; }

    // --- Statistics ---

    /// Get the number of blocks accepted since startup.
    uint64_t get_blocks_accepted() const { return blocks_accepted_; }

    /// Get the number of blocks rejected since startup.
    uint64_t get_blocks_rejected() const { return blocks_rejected_; }

    /// Get the hash of the most recently accepted block.
    uint256 get_last_accepted_hash() const;

    /// Get the time of the most recently accepted block.
    int64_t get_last_accepted_time() const;

private:
    ChainState& chain_;
    NetManager* net_;
    Mempool* mempool_;

    bool relay_enabled_ = true;
    bool mempool_update_enabled_ = true;
    int64_t min_peer_block_interval_ = 2;  // seconds

    // Statistics
    uint64_t blocks_accepted_ = 0;
    uint64_t blocks_rejected_ = 0;
    uint256 last_accepted_hash_;
    int64_t last_accepted_time_ = 0;

    // Rate limiting per peer
    std::mutex rate_mutex_;
    std::map<uint64_t, int64_t> last_block_time_;

    // Recently seen block hashes for duplicate detection
    std::mutex seen_mutex_;
    std::vector<uint256> recent_hashes_;
    static constexpr size_t MAX_RECENT_HASHES = 1000;

    /// Core validation and connection logic.
    SubmitResult validate_and_connect(const CBlock& block);

    /// Relay a block to connected peers.
    void relay_block(const CBlock& block);

    /// Update the mempool after a block is accepted.
    void update_mempool(const CBlock& block);

    /// Check rate limiting for a peer.
    bool check_rate_limit(uint64_t peer_id);

    /// Check if a block hash has been recently seen.
    bool is_recently_seen(const uint256& hash);

    /// Add a hash to the recently seen set.
    void mark_seen(const uint256& hash);

    /// Record timing for rate limiting.
    void record_peer_block(uint64_t peer_id);
};

// ---------------------------------------------------------------------------
// Free functions (backward-compatible API)
// ---------------------------------------------------------------------------

/// Submit a fully assembled block to the chain.
SubmitResult submit_block(ChainState& chain, const CBlock& block);

/// Deserialize a block from raw bytes (wire format).
bool deserialize_block(const std::vector<uint8_t>& data, CBlock& block);

/// Serialize a block to raw bytes (wire format).
std::vector<uint8_t> serialize_block(const CBlock& block);

/// Validate basic block structure without chain context.
/// Checks: non-empty transactions, valid coinbase, no duplicates, size limits.
bool check_block_structure(const CBlock& block, std::string& error);

/// Compute the block hash for display purposes.
std::string get_block_hash_hex(const CBlock& block);

} // namespace flow

#endif // FLOWCOIN_MINING_SUBMITBLOCK_H
