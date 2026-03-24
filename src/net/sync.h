// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Initial Block Download (IBD) sync manager.
// Coordinates header-first sync: download all headers from the best peer,
// then download full blocks in parallel using a sliding window.
// Headers are validated header-only (cheap). Full blocks are downloaded
// in parallel but applied sequentially (because model state is sequential).
//
// State machine:
//   IDLE -> HEADERS -> BLOCKS -> DONE -> IDLE
//
// The manager handles stalled downloads, peer switching, and buffered
// out-of-order block arrival.

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
    };
    Progress get_progress() const;

private:
    ChainState& chain_;
    NetManager& net_;
    State state_ = State::IDLE;
    mutable std::mutex mutex_;

    // Header sync
    uint64_t header_sync_target_ = 0;
    uint64_t headers_received_ = 0;
    uint64_t header_sync_peer_ = 0;  // peer ID for header sync

    // Block download
    struct BlockRequest {
        uint256 hash;
        uint64_t height;
        uint64_t peer_id;
        int64_t request_time;
    };

    static constexpr int DOWNLOAD_WINDOW = 16;
    static constexpr int REQUEST_TIMEOUT_SECS = 60;
    static constexpr int MAX_HEADERS_PER_MSG = 2000;

    // Blocks requested but not yet received
    std::map<uint64_t, BlockRequest> inflight_;  // height -> request

    // Downloaded but not yet applied (waiting for sequential application)
    std::map<uint64_t, CBlock> download_buffer_;

    // Next height to apply
    uint64_t next_apply_height_ = 0;

    // Total blocks to download for progress reporting
    uint64_t blocks_download_target_ = 0;
    uint64_t blocks_applied_ = 0;

    // Request blocks for the download window
    void fill_download_window();

    // Apply buffered blocks sequentially
    void apply_buffered_blocks();

    // Build block locator for getheaders (Bitcoin Core algorithm)
    std::vector<uint256> build_locator() const;

    // Select best peer for downloading
    Peer* select_download_peer() const;

    // Handle stalled requests
    void check_timeouts();

    // Transition to DONE state
    void finish_sync();

    // Send getheaders to a peer
    void send_getheaders(Peer& peer, const std::vector<uint256>& locator);

    // Send getdata for a specific block hash
    void send_getdata_block(Peer& peer, const uint256& block_hash);
};

} // namespace flow

#endif // FLOWCOIN_NET_SYNC_H
