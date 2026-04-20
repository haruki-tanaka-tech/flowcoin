// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Initial Block Download (IBD) sync manager.
// Coordinates header-first sync: download all headers from the best peer,
// then download full blocks in parallel using a sliding window.
// Headers are validated header-only (cheap). Full blocks are downloaded
// in parallel but applied sequentially (because model state is sequential).
//
// Features:
//   - Assume-valid optimization: skip signature checks for blocks below
//     a known-good hash checkpoint
//   - Parallel header download from multiple peers
//   - Block download scoring: prefer peers with better throughput
//   - Stale tip detection: if tip hasn't changed in 30 minutes, try
//     different peer
//   - Progress reporting: percentage, ETA, blocks/second
//   - Compact block download for recent blocks (when near tip)
//   - Automatic IBD-to-steady-state transition
//
// State machine:
//   IDLE -> HEADERS -> BLOCKS -> DONE -> IDLE

#ifndef FLOWCOIN_NET_SYNC_H
#define FLOWCOIN_NET_SYNC_H

#include "chain/chainstate.h"
#include "net/net.h"
#include "net/peer.h"
#include "primitives/block.h"
#include "util/types.h"

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

class SyncManager {
public:
    SyncManager(ChainState& chain, NetManager& net);

    // Current sync state
    enum class State {
        IDLE,           // Synced, waiting for new blocks
        HEADERS,        // Downloading headers
        BLOCKS,         // Downloading full blocks
        DONE            // IBD complete, switching to steady state
    };

    State state() const { return state_; }
    bool is_syncing() const { return state_ != State::IDLE; }
    bool is_ibd() const { return state_ == State::HEADERS || state_ == State::BLOCKS; }

    // Start IBD with a peer that has a higher chain
    void start_sync(Peer& peer);

    // Process received headers (from getheaders response)
    void on_headers(Peer& peer, const std::vector<CBlockHeader>& headers);

    // Process received block (from getdata response)
    void on_block(Peer& peer, const CBlock& block);

    // Periodic tick (check for stalled downloads, request more)
    void tick();

    // Get sync progress
    struct Progress {
        uint64_t headers_downloaded;
        uint64_t headers_total;
        uint64_t blocks_downloaded;
        uint64_t blocks_total;
        double percentage;
        double blocks_per_second;
        int64_t eta_seconds;          // Estimated time remaining
        std::string status_string;    // Human-readable status
    };
    Progress get_progress() const;

    // Assume-valid configuration
    void set_assume_valid(const uint256& hash) { assume_valid_hash_ = hash; }
    const uint256& assume_valid_hash() const { return assume_valid_hash_; }
    bool is_assume_valid_block(const uint256& hash) const;

    // Check if we're past the assume-valid point
    bool past_assume_valid() const;

    // Stale tip detection
    bool has_stale_tip() const;

    // Force re-sync from a different peer
    void reset_sync();

private:
    ChainState& chain_;
    NetManager& net_;
    State state_ = State::IDLE;
    mutable std::mutex mutex_;

    // Header sync
    uint64_t header_sync_target_ = 0;
    uint64_t headers_received_ = 0;
    uint64_t header_sync_peer_ = 0;  // peer ID for header sync

    // Multi-peer header download tracking
    struct HeaderRequest {
        uint64_t peer_id;
        int64_t request_time;
        uint256 last_hash;  // last hash in the locator
    };
    std::vector<HeaderRequest> header_requests_;

    // Block download
    struct BlockRequest {
        uint256 hash;
        uint64_t height;
        uint64_t peer_id;
        int64_t request_time;
        bool use_compact;  // request as compact block
    };

    static constexpr int DOWNLOAD_WINDOW = 16;
    static constexpr int REQUEST_TIMEOUT_SECS = 60;
    static constexpr int MAX_HEADERS_PER_MSG = 2000;
    static constexpr int64_t STALE_TIP_THRESHOLD = 30 * 60;  // 30 minutes
    static constexpr int64_t NEAR_TIP_THRESHOLD = 24 * 3600;  // 24 hours

    // Blocks requested but not yet received
    std::map<uint64_t, BlockRequest> inflight_;  // height -> request

    // Downloaded but not yet applied (waiting for sequential application)
    std::map<uint64_t, CBlock> download_buffer_;

    // Next height to apply
    uint64_t next_apply_height_ = 0;

    // Total blocks to download for progress reporting
    uint64_t blocks_download_target_ = 0;
    uint64_t blocks_applied_ = 0;

    // Timing for progress/ETA
    int64_t sync_start_time_ = 0;
    int64_t last_tip_change_time_ = 0;
    uint64_t last_tip_height_ = 0;

    // Per-peer throughput tracking for download scoring
    struct PeerScore {
        uint64_t blocks_delivered = 0;
        uint64_t bytes_delivered = 0;
        int64_t total_delivery_time = 0;  // sum of (recv_time - request_time)
        int stall_count = 0;

        double throughput() const {
            if (total_delivery_time <= 0) return 1.0;
            return static_cast<double>(blocks_delivered) /
                   static_cast<double>(total_delivery_time);
        }
    };
    std::map<uint64_t, PeerScore> peer_scores_;  // peer_id -> score

    // Assume-valid optimization
    uint256 assume_valid_hash_;
    bool assume_valid_found_ = false;
    uint64_t assume_valid_height_ = 0;

    // Request blocks for the download window
    void fill_download_window();

    // Apply buffered blocks sequentially
    void apply_buffered_blocks();

    // Build block locator for getheaders (Bitcoin Core algorithm)
    std::vector<uint256> build_locator() const;

    // Select best peer for downloading (throughput-scored)
    Peer* select_download_peer() const;

    // Select peers for parallel header download
    std::vector<Peer*> select_header_peers() const;

    // Handle stalled requests
    void check_timeouts();

    // Transition to DONE state
    void finish_sync();

    // Send getheaders to a peer
    void send_getheaders(Peer& peer, const std::vector<uint256>& locator);

    // Send getdata for a specific block hash
    void send_getdata_block(Peer& peer, const uint256& block_hash);

    // Check if we're near the tip of the chain (within 24 hours)
    bool is_near_tip() const;

    // Update peer download score after receiving a block
    void update_peer_score(uint64_t peer_id, int64_t delivery_time, uint64_t bytes);

    // Handle stale tip: try switching to a different sync peer
    void handle_stale_tip();

    // Log progress with ETA
    void log_progress();
};

} // namespace flow

#endif // FLOWCOIN_NET_SYNC_H
