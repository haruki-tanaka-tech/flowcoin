// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// IBD sync manager implementation.
// Header-first synchronization with parallel block download.
//
// Algorithm:
// 1. Pick the peer with the highest reported chain height
// 2. Download headers using getheaders with a block locator
// 3. Validate each header (checks 1-11, 13-14)
// 4. Once all headers are downloaded, switch to block download phase
// 5. Download up to DOWNLOAD_WINDOW blocks in parallel from multiple peers
// 6. Apply blocks sequentially as they arrive (model state is sequential)
// 7. Re-request stalled blocks from different peers
// 8. When all blocks are applied, transition to IDLE (steady state)

#include "net/sync.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "util/time.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace flow {

// ════════════════════════════════════════════════════════════════════════════
// Constructor
// ════════════════════════════════════════════════════════════════════════════

SyncManager::SyncManager(ChainState& chain, NetManager& net)
    : chain_(chain)
    , net_(net)
{
}

// ════════════════════════════════════════════════════════════════════════════
// start_sync — begin IBD with a peer that has a higher chain
// ════════════════════════════════════════════════════════════════════════════

void SyncManager::start_sync(Peer& peer) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != State::IDLE) {
        // Already syncing
        return;
    }

    uint64_t our_height = chain_.height();
    uint64_t their_height = peer.start_height();

    if (their_height <= our_height) {
        // Peer doesn't have a longer chain
        return;
    }

    fprintf(stderr, "SyncManager: starting IBD from height %lu to %lu "
            "with peer %lu\n",
            static_cast<unsigned long>(our_height),
            static_cast<unsigned long>(their_height),
            static_cast<unsigned long>(peer.id()));

    state_ = State::HEADERS;
    header_sync_target_ = their_height;
    headers_received_ = our_height;
    header_sync_peer_ = peer.id();

    // Send initial getheaders request
    std::vector<uint256> locator = build_locator();
    send_getheaders(peer, locator);
}

// ════════════════════════════════════════════════════════════════════════════
// build_locator — Bitcoin Core's logarithmic block locator
// ════════════════════════════════════════════════════════════════════════════

std::vector<uint256> SyncManager::build_locator() const {
    // Walk backwards from our tip, adding block hashes.
    // For the first 10 entries, step back by 1.
    // After that, double the step size each time.
    // Always include genesis at the end.

    std::vector<uint256> locator;
    CBlockIndex* tip = chain_.tip();

    if (!tip) {
        return locator;
    }

    CBlockIndex* walk = tip;
    int step = 1;
    int count = 0;

    while (walk) {
        locator.push_back(walk->hash);

        // Move back 'step' blocks
        for (int i = 0; i < step && walk->prev; i++) {
            walk = walk->prev;
        }

        // After 10 entries, start doubling the step
        count++;
        if (count > 10) {
            step *= 2;
        }

        // If we've reached genesis, add it and stop
        if (!walk->prev) {
            if (locator.empty() || locator.back() != walk->hash) {
                locator.push_back(walk->hash);
            }
            break;
        }
    }

    return locator;
}

// ════════════════════════════════════════════════════════════════════════════
// on_headers — process received headers
// ════════════════════════════════════════════════════════════════════════════

void SyncManager::on_headers(Peer& peer,
                              const std::vector<CBlockHeader>& headers) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != State::HEADERS) {
        return;
    }

    if (headers.empty()) {
        // No more headers — peer has sent everything it has.
        // Transition to block download phase.
        fprintf(stderr, "SyncManager: header sync complete "
                "(%lu headers in tree)\n",
                static_cast<unsigned long>(chain_.block_tree().size()));

        // Determine the range of blocks we need to download
        CBlockIndex* our_tip = chain_.tip();
        uint64_t our_height = our_tip ? our_tip->height : 0;

        // Find the best tip in the block tree (may be ahead of our connected tip)
        // We need to walk the block tree to find headers that don't have data yet.
        // For simplicity, we download from our_height + 1 to header_sync_target_.
        next_apply_height_ = our_height + 1;
        blocks_download_target_ = header_sync_target_;
        blocks_applied_ = 0;

        if (next_apply_height_ > blocks_download_target_) {
            // Nothing to download
            finish_sync();
            return;
        }

        state_ = State::BLOCKS;
        inflight_.clear();
        download_buffer_.clear();

        fprintf(stderr, "SyncManager: switching to block download, "
                "range [%lu, %lu]\n",
                static_cast<unsigned long>(next_apply_height_),
                static_cast<unsigned long>(blocks_download_target_));

        fill_download_window();
        return;
    }

    // Validate and accept each header
    int accepted = 0;
    for (const auto& hdr : headers) {
        consensus::ValidationState vstate;
        CBlockIndex* idx = chain_.accept_header(hdr, vstate);
        if (idx) {
            accepted++;
            headers_received_ = std::max(headers_received_, idx->height);
        } else {
            // Header validation failed — misbehavior
            fprintf(stderr, "SyncManager: header validation failed from peer %lu: %s\n",
                    static_cast<unsigned long>(peer.id()),
                    vstate.to_string().c_str());
            peer.add_misbehavior(20);

            if (peer.should_ban()) {
                net_.disconnect(peer, "header validation failure");
                state_ = State::IDLE;
                return;
            }
            break;
        }
    }

    fprintf(stderr, "SyncManager: accepted %d/%zu headers "
            "(best: %lu / target: %lu)\n",
            accepted, headers.size(),
            static_cast<unsigned long>(headers_received_),
            static_cast<unsigned long>(header_sync_target_));

    // Request more headers if we got a full batch
    if (headers.size() >= static_cast<size_t>(MAX_HEADERS_PER_MSG)) {
        std::vector<uint256> locator = build_locator();
        send_getheaders(peer, locator);
    } else {
        // Got fewer than max — peer has no more headers
        // Check if we reached the target
        if (headers_received_ >= header_sync_target_) {
            // All headers downloaded, transition to blocks
            CBlockIndex* our_tip = chain_.tip();
            uint64_t our_height = our_tip ? our_tip->height : 0;

            next_apply_height_ = our_height + 1;
            blocks_download_target_ = headers_received_;
            blocks_applied_ = 0;

            if (next_apply_height_ > blocks_download_target_) {
                finish_sync();
                return;
            }

            state_ = State::BLOCKS;
            inflight_.clear();
            download_buffer_.clear();

            fprintf(stderr, "SyncManager: header sync complete, "
                    "downloading blocks [%lu, %lu]\n",
                    static_cast<unsigned long>(next_apply_height_),
                    static_cast<unsigned long>(blocks_download_target_));

            fill_download_window();
        } else {
            // Request more from a potentially different peer
            std::vector<uint256> locator = build_locator();
            send_getheaders(peer, locator);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// on_block — process a received block
// ════════════════════════════════════════════════════════════════════════════

void SyncManager::on_block(Peer& peer, const CBlock& block) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != State::BLOCKS) {
        // Not in block download phase — this is a new block announcement
        // during steady state. Let chainstate handle it directly.
        return;
    }

    uint64_t height = block.height;

    // Remove from inflight
    auto it = inflight_.find(height);
    if (it != inflight_.end()) {
        inflight_.erase(it);
    }

    // Add to download buffer
    download_buffer_[height] = block;

    // Try to apply buffered blocks sequentially
    apply_buffered_blocks();

    // Request more blocks to fill the window
    fill_download_window();

    // Check if we're done
    if (next_apply_height_ > blocks_download_target_ &&
        inflight_.empty() && download_buffer_.empty()) {
        finish_sync();
    }
}

// ════════════════════════════════════════════════════════════════════════════
// fill_download_window — request blocks up to DOWNLOAD_WINDOW ahead
// ════════════════════════════════════════════════════════════════════════════

void SyncManager::fill_download_window() {
    // Request blocks starting from next_apply_height_ up to
    // next_apply_height_ + DOWNLOAD_WINDOW, skipping those already
    // in-flight or in the download buffer.

    int requests_made = 0;
    uint64_t height = next_apply_height_;

    while (height <= blocks_download_target_ &&
           static_cast<int>(inflight_.size()) < DOWNLOAD_WINDOW) {

        // Skip if already in-flight
        if (inflight_.count(height) > 0) {
            height++;
            continue;
        }

        // Skip if already buffered
        if (download_buffer_.count(height) > 0) {
            height++;
            continue;
        }

        // Find the block index for this height to get the hash
        // Walk from genesis to find the block at this height.
        // For efficiency, we look up by walking the header chain.
        CBlockIndex* idx = nullptr;
        {
            // We need to find the block index at this height on the best
            // header chain. Walk from the highest header backwards.
            // This is O(n) but only happens during IBD.
            CBlockIndex* walk = chain_.block_tree().best_tip();

            // If the best tip is at our connected chain height and headers
            // go further, we need to find the header at 'height'.
            // Use the block tree to find it.

            // Walk up from genesis along the path to the target tip.
            // For IBD, we need to find the hash at each height.
            // A better approach: walk backwards from the best header tip.

            // Find the header chain tip (may be ahead of connected tip)
            // We scan all block index entries to find one at this height
            // that is on the main header chain.

            // Simple approach: walk back from the best tip
            // The best tip in the tree is the one with highest height
            // and BLOCK_HEADER_VALID status.

            // Start from best_tip and walk back to find the right height
            walk = chain_.block_tree().best_tip();

            // Walk forward approach: we know the tree, find block at height
            // by walking backward from any tip at or above this height.
            while (walk && walk->height > height) {
                walk = walk->prev;
            }

            if (walk && walk->height == height) {
                idx = walk;
            }
        }

        if (!idx) {
            // No header for this height yet — stop requesting
            break;
        }

        // Select a peer to download from
        Peer* download_peer = select_download_peer();
        if (!download_peer) {
            // No available peers
            break;
        }

        // Record the request
        BlockRequest req;
        req.hash = idx->hash;
        req.height = height;
        req.peer_id = download_peer->id();
        req.request_time = GetTime();
        inflight_[height] = req;

        // Send getdata
        send_getdata_block(*download_peer, idx->hash);
        requests_made++;
        height++;
    }

    if (requests_made > 0) {
        fprintf(stderr, "SyncManager: requested %d blocks "
                "(inflight: %zu, buffered: %zu, next_apply: %lu)\n",
                requests_made, inflight_.size(), download_buffer_.size(),
                static_cast<unsigned long>(next_apply_height_));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// apply_buffered_blocks — process download_buffer_ sequentially
// ════════════════════════════════════════════════════════════════════════════

void SyncManager::apply_buffered_blocks() {
    // Apply blocks in order starting from next_apply_height_
    while (true) {
        auto it = download_buffer_.find(next_apply_height_);
        if (it == download_buffer_.end()) {
            break;  // Next block not yet downloaded
        }

        const CBlock& block = it->second;

        // Accept the block through chainstate
        consensus::ValidationState vstate;
        bool accepted = chain_.accept_block(block, vstate);

        if (!accepted) {
            fprintf(stderr, "SyncManager: block validation failed at "
                    "height %lu: %s\n",
                    static_cast<unsigned long>(next_apply_height_),
                    vstate.to_string().c_str());

            // Remove from buffer and skip — the header was valid but the
            // block body failed. This should not happen if the header chain
            // is valid. Mark as internal error and stop sync.
            download_buffer_.erase(it);

            // Try to continue with the next block
            // (aggressive — we could also abort sync here)
            next_apply_height_++;
            blocks_applied_++;
            continue;
        }

        blocks_applied_++;

        // Log progress periodically
        if (blocks_applied_ % 100 == 0 || next_apply_height_ >= blocks_download_target_) {
            uint64_t total = blocks_download_target_ - (next_apply_height_ - blocks_applied_);
            double pct = total > 0
                ? (static_cast<double>(blocks_applied_) / static_cast<double>(total)) * 100.0
                : 100.0;
            fprintf(stderr, "SyncManager: applied block %lu (%.1f%%)\n",
                    static_cast<unsigned long>(next_apply_height_),
                    pct);
        }

        download_buffer_.erase(it);
        next_apply_height_++;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// select_download_peer — pick the best peer for block download
// ════════════════════════════════════════════════════════════════════════════

Peer* SyncManager::select_download_peer() const {
    auto peers = net_.get_peers();
    Peer* best = nullptr;
    int64_t best_latency = INT64_MAX;

    for (Peer* p : peers) {
        if (p->state() != PeerState::HANDSHAKE_DONE) continue;
        if (p->should_ban()) continue;

        // Prefer peers with lower latency and higher start_height
        if (p->start_height() >= next_apply_height_) {
            int64_t latency = p->ping_latency_us();
            if (latency <= 0) latency = INT64_MAX / 2;  // unknown latency

            if (latency < best_latency) {
                best_latency = latency;
                best = p;
            }
        }
    }

    // Fallback: any handshaked peer
    if (!best) {
        for (Peer* p : peers) {
            if (p->state() == PeerState::HANDSHAKE_DONE && !p->should_ban()) {
                best = p;
                break;
            }
        }
    }

    return best;
}

// ════════════════════════════════════════════════════════════════════════════
// check_timeouts — re-request stalled blocks from different peers
// ════════════════════════════════════════════════════════════════════════════

void SyncManager::check_timeouts() {
    int64_t now = GetTime();
    std::vector<uint64_t> timed_out;

    for (const auto& [height, req] : inflight_) {
        if (now - req.request_time > REQUEST_TIMEOUT_SECS) {
            timed_out.push_back(height);
        }
    }

    for (uint64_t height : timed_out) {
        auto it = inflight_.find(height);
        if (it == inflight_.end()) continue;

        BlockRequest& req = it->second;

        fprintf(stderr, "SyncManager: block request timed out at "
                "height %lu (peer %lu, %ld seconds)\n",
                static_cast<unsigned long>(height),
                static_cast<unsigned long>(req.peer_id),
                static_cast<long>(now - req.request_time));

        // Add misbehavior to the stalling peer
        auto peers = net_.get_peers();
        for (Peer* p : peers) {
            if (p->id() == req.peer_id) {
                p->add_misbehavior(5);
                break;
            }
        }

        // Re-request from a different peer
        Peer* new_peer = select_download_peer();
        if (new_peer && new_peer->id() != req.peer_id) {
            req.peer_id = new_peer->id();
            req.request_time = now;
            send_getdata_block(*new_peer, req.hash);

            fprintf(stderr, "SyncManager: re-requested block at height %lu "
                    "from peer %lu\n",
                    static_cast<unsigned long>(height),
                    static_cast<unsigned long>(new_peer->id()));
        } else {
            // No alternative peer available — keep waiting
            req.request_time = now;  // Reset timeout
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// tick — periodic maintenance
// ════════════════════════════════════════════════════════════════════════════

void SyncManager::tick() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ == State::IDLE || state_ == State::DONE) {
        return;
    }

    if (state_ == State::HEADERS) {
        // Check if our header sync peer is still connected
        bool peer_alive = false;
        auto peers = net_.get_peers();
        for (Peer* p : peers) {
            if (p->id() == header_sync_peer_ &&
                p->state() == PeerState::HANDSHAKE_DONE) {
                peer_alive = true;
                break;
            }
        }

        if (!peer_alive) {
            fprintf(stderr, "SyncManager: header sync peer disconnected, "
                    "finding new peer\n");

            // Find a new peer with a higher chain
            Peer* new_peer = nullptr;
            uint64_t best_height = chain_.height();

            for (Peer* p : peers) {
                if (p->state() == PeerState::HANDSHAKE_DONE &&
                    p->start_height() > best_height &&
                    !p->should_ban()) {
                    if (!new_peer || p->start_height() > new_peer->start_height()) {
                        new_peer = p;
                    }
                }
            }

            if (new_peer) {
                header_sync_peer_ = new_peer->id();
                header_sync_target_ = new_peer->start_height();
                std::vector<uint256> locator = build_locator();
                send_getheaders(*new_peer, locator);
                fprintf(stderr, "SyncManager: switched header sync to peer %lu "
                        "(target height %lu)\n",
                        static_cast<unsigned long>(new_peer->id()),
                        static_cast<unsigned long>(header_sync_target_));
            } else {
                fprintf(stderr, "SyncManager: no suitable peers for header sync, "
                        "aborting\n");
                state_ = State::IDLE;
            }
        }
    }

    if (state_ == State::BLOCKS) {
        check_timeouts();
        fill_download_window();

        // Check if we're done
        if (next_apply_height_ > blocks_download_target_ &&
            inflight_.empty() && download_buffer_.empty()) {
            finish_sync();
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// finish_sync — transition to IDLE
// ════════════════════════════════════════════════════════════════════════════

void SyncManager::finish_sync() {
    state_ = State::DONE;

    fprintf(stderr, "SyncManager: IBD complete, chain height %lu\n",
            static_cast<unsigned long>(chain_.height()));

    // Clear state
    inflight_.clear();
    download_buffer_.clear();

    // Transition to idle
    state_ = State::IDLE;
}

// ════════════════════════════════════════════════════════════════════════════
// get_progress — sync progress for RPC / UI
// ════════════════════════════════════════════════════════════════════════════

SyncManager::Progress SyncManager::get_progress() const {
    std::lock_guard<std::mutex> lock(mutex_);

    Progress p{};

    if (state_ == State::IDLE) {
        uint64_t h = chain_.height();
        p.headers_downloaded = h;
        p.headers_total = h;
        p.blocks_downloaded = h;
        p.blocks_total = h;
        p.percentage = 100.0;
        return p;
    }

    p.headers_downloaded = headers_received_;
    p.headers_total = header_sync_target_;

    if (state_ == State::HEADERS) {
        p.blocks_downloaded = chain_.height();
        p.blocks_total = header_sync_target_;
        if (p.headers_total > 0) {
            p.percentage = (static_cast<double>(p.headers_downloaded)
                            / static_cast<double>(p.headers_total)) * 50.0;
        }
    } else {
        p.blocks_downloaded = next_apply_height_ > 0 ? next_apply_height_ - 1 : 0;
        p.blocks_total = blocks_download_target_;
        if (p.blocks_total > 0) {
            double header_pct = 50.0;
            double block_pct = (static_cast<double>(blocks_applied_)
                                / static_cast<double>(p.blocks_total)) * 50.0;
            p.percentage = header_pct + block_pct;
        }
    }

    return p;
}

// ════════════════════════════════════════════════════════════════════════════
// Wire protocol helpers
// ════════════════════════════════════════════════════════════════════════════

void SyncManager::send_getheaders(Peer& peer,
                                   const std::vector<uint256>& locator) {
    // Serialize getheaders payload:
    //   [compact_size: locator count]
    //   [32 bytes * locator_count: locator hashes]
    //   [32 bytes: hash_stop (zero = get everything)]

    DataWriter w;
    w.write_compact_size(locator.size());
    for (const auto& hash : locator) {
        w.write_bytes(hash.data(), 32);
    }

    // hash_stop = zero (get everything up to their tip)
    uint256 zero;
    zero.set_null();
    w.write_bytes(zero.data(), 32);

    std::vector<uint8_t> msg = build_message(
        net_.magic(), NetCmd::GETHEADERS, w.data());
    net_.send_to(peer, msg);
}

void SyncManager::send_getdata_block(Peer& peer, const uint256& block_hash) {
    // Serialize getdata payload:
    //   [compact_size: 1 item]
    //   [4 bytes: type = INV_BLOCK]
    //   [32 bytes: hash]

    DataWriter w;
    w.write_compact_size(1);
    w.write_u32_le(INV_BLOCK);
    w.write_bytes(block_hash.data(), 32);

    std::vector<uint8_t> msg = build_message(
        net_.magic(), NetCmd::GETDATA, w.data());
    net_.send_to(peer, msg);
}

} // namespace flow
