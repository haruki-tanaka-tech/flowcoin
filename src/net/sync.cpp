// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// IBD sync manager implementation.
// Header-first synchronization with parallel block download, assume-valid
// optimization, throughput-scored peer selection, stale tip detection,
// and progress reporting with ETA.
//
// Algorithm:
// 1. Pick the peer with the highest reported chain height
// 2. Download headers using getheaders with a block locator
// 3. Validate each header (checks 1-11, 13-14)
// 4. Once all headers are downloaded, switch to block download phase
// 5. Download up to DOWNLOAD_WINDOW blocks in parallel from multiple peers
// 6. Apply blocks sequentially as they arrive (model state is sequential)
// 7. For blocks below assume-valid height, skip signature verification
// 8. Re-request stalled blocks from different peers
// 9. When all blocks are applied, transition to IDLE (steady state)

#include "net/sync.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "util/time.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace flow {

// ============================================================================
// Constructor
// ============================================================================

SyncManager::SyncManager(ChainState& chain, NetManager& net)
    : chain_(chain)
    , net_(net)
{
}

// ============================================================================
// start_sync — begin IBD with a peer that has a higher chain
// ============================================================================

void SyncManager::start_sync(Peer& peer) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != State::IDLE) {
        return;
    }

    uint64_t our_height = chain_.height();
    uint64_t their_height = peer.start_height();

    if (their_height <= our_height) {
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
    sync_start_time_ = GetTime();
    last_tip_change_time_ = sync_start_time_;
    last_tip_height_ = our_height;
    blocks_applied_ = 0;
    peer_scores_.clear();
    header_requests_.clear();

    // Send initial getheaders request
    std::vector<uint256> locator = build_locator();
    send_getheaders(peer, locator);
}

// ============================================================================
// build_locator — Bitcoin Core's logarithmic block locator
// ============================================================================

std::vector<uint256> SyncManager::build_locator() const {
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

        for (int i = 0; i < step && walk->prev; i++) {
            walk = walk->prev;
        }

        count++;
        if (count > 10) {
            step *= 2;
        }

        if (!walk->prev) {
            if (locator.empty() || locator.back() != walk->hash) {
                locator.push_back(walk->hash);
            }
            break;
        }
    }

    return locator;
}

// ============================================================================
// on_headers — process received headers
// ============================================================================

void SyncManager::on_headers(Peer& peer,
                              const std::vector<CBlockHeader>& headers) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != State::HEADERS) {
        return;
    }

    if (headers.empty()) {
        // No more headers — transition to block download phase
        fprintf(stderr, "SyncManager: header sync complete "
                "(%lu headers in tree)\n",
                static_cast<unsigned long>(chain_.block_tree().size()));

        CBlockIndex* our_tip = chain_.tip();
        uint64_t our_height = our_tip ? our_tip->height : 0;

        next_apply_height_ = our_height + 1;
        blocks_download_target_ = header_sync_target_;
        blocks_applied_ = 0;

        if (next_apply_height_ > blocks_download_target_) {
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

            // Check for assume-valid block
            if (!assume_valid_hash_.is_null() && idx->hash == assume_valid_hash_) {
                assume_valid_found_ = true;
                assume_valid_height_ = idx->height;
                fprintf(stderr, "SyncManager: found assume-valid block at height %lu\n",
                        static_cast<unsigned long>(assume_valid_height_));
            }
        } else {
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

    // Update tip change tracking
    if (accepted > 0) {
        last_tip_change_time_ = GetTime();
    }

    // Request more headers if we got a full batch
    if (headers.size() >= static_cast<size_t>(MAX_HEADERS_PER_MSG)) {
        std::vector<uint256> locator = build_locator();
        send_getheaders(peer, locator);
    } else {
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
            std::vector<uint256> locator = build_locator();
            send_getheaders(peer, locator);
        }
    }
}

// ============================================================================
// on_block — process a received block
// ============================================================================

void SyncManager::on_block(Peer& peer, const CBlock& block) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != State::BLOCKS) {
        return;
    }

    uint64_t height = block.height;

    // Calculate delivery time for peer scoring
    auto it = inflight_.find(height);
    if (it != inflight_.end()) {
        int64_t now = GetTime();
        int64_t delivery_time = now - it->second.request_time;
        update_peer_score(peer.id(), delivery_time, 0);
        inflight_.erase(it);
    }

    // Update synced_blocks on the peer
    peer.set_synced_blocks(std::max(peer.synced_blocks(), height));

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

// ============================================================================
// fill_download_window
// ============================================================================

void SyncManager::fill_download_window() {
    int requests_made = 0;
    uint64_t height = next_apply_height_;

    while (height <= blocks_download_target_ &&
           static_cast<int>(inflight_.size()) < DOWNLOAD_WINDOW) {

        if (inflight_.count(height) > 0) {
            height++;
            continue;
        }

        if (download_buffer_.count(height) > 0) {
            height++;
            continue;
        }

        // Find the block index for this height
        CBlockIndex* idx = nullptr;
        {
            CBlockIndex* walk = chain_.block_tree().best_tip();
            while (walk && walk->height > height) {
                walk = walk->prev;
            }
            if (walk && walk->height == height) {
                idx = walk;
            }
        }

        if (!idx) {
            break;
        }

        Peer* download_peer = select_download_peer();
        if (!download_peer) {
            break;
        }

        BlockRequest req;
        req.hash = idx->hash;
        req.height = height;
        req.peer_id = download_peer->id();
        req.request_time = GetTime();
        req.use_compact = is_near_tip() && download_peer->supports_compact_blocks();
        inflight_[height] = req;

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

// ============================================================================
// apply_buffered_blocks — with assume-valid optimization
// ============================================================================

void SyncManager::apply_buffered_blocks() {
    while (true) {
        auto it = download_buffer_.find(next_apply_height_);
        if (it == download_buffer_.end()) {
            break;
        }

        const CBlock& block = it->second;

        consensus::ValidationState vstate;

        // Assume-valid optimization: if this block is below the assume-valid
        // height, we can skip expensive signature verification (Check 15).
        // The header chain has already been fully validated.
        bool skip_scripts = false;
        if (assume_valid_found_ && next_apply_height_ <= assume_valid_height_) {
            skip_scripts = true;
        }

        bool accepted;
        // accept_block handles assume-valid internally based on set_assume_valid()
        accepted = chain_.accept_block(block, vstate);

        if (!accepted) {
            fprintf(stderr, "SyncManager: block validation failed at "
                    "height %lu: %s\n",
                    static_cast<unsigned long>(next_apply_height_),
                    vstate.to_string().c_str());

            download_buffer_.erase(it);
            next_apply_height_++;
            blocks_applied_++;
            continue;
        }

        blocks_applied_++;

        // Update tip change tracking
        last_tip_change_time_ = GetTime();
        last_tip_height_ = next_apply_height_;

        // Log progress periodically
        if (blocks_applied_ % 100 == 0 || next_apply_height_ >= blocks_download_target_) {
            log_progress();
        }

        download_buffer_.erase(it);
        next_apply_height_++;
    }
}

// ============================================================================
// select_download_peer — throughput-scored selection
// ============================================================================

Peer* SyncManager::select_download_peer() const {
    auto peers = net_.get_peers();
    Peer* best = nullptr;
    double best_score = -1.0;

    for (Peer* p : peers) {
        if (p->state() != PeerState::HANDSHAKE_DONE) continue;
        if (p->should_ban()) continue;
        if (p->start_height() < next_apply_height_) continue;

        double score = 1.0;

        // Factor in throughput from peer scoring
        auto sit = peer_scores_.find(p->id());
        if (sit != peer_scores_.end()) {
            score = sit->second.throughput();
            // Penalize peers that have stalled
            score /= (1.0 + sit->second.stall_count * 0.5);
        }

        // Factor in latency
        int64_t latency = p->ping_latency_us();
        if (latency > 0) {
            double latency_ms = static_cast<double>(latency) / 1000.0;
            score /= std::max(1.0, latency_ms / 100.0);
        }

        // Slight preference for outbound peers
        if (!p->is_inbound()) {
            score *= 1.1;
        }

        if (score > best_score) {
            best_score = score;
            best = p;
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

// ============================================================================
// select_header_peers — multiple peers for parallel header download
// ============================================================================

std::vector<Peer*> SyncManager::select_header_peers() const {
    auto peers = net_.get_peers();
    std::vector<Peer*> result;

    for (Peer* p : peers) {
        if (p->state() == PeerState::HANDSHAKE_DONE &&
            !p->should_ban() &&
            p->start_height() > chain_.height()) {
            result.push_back(p);
        }
    }

    // Sort by start_height descending (prefer peers with tallest chains)
    std::sort(result.begin(), result.end(),
              [](const Peer* a, const Peer* b) {
                  return a->start_height() > b->start_height();
              });

    // Return at most 3 peers for parallel header download
    if (result.size() > 3) {
        result.resize(3);
    }

    return result;
}

// ============================================================================
// check_timeouts — re-request stalled blocks from different peers
// ============================================================================

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

        // Update peer score: mark a stall
        auto& ps = peer_scores_[req.peer_id];
        ps.stall_count++;

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
            req.request_time = now;
        }
    }
}

// ============================================================================
// tick — periodic maintenance
// ============================================================================

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

        // Stale tip detection during header sync
        if (has_stale_tip()) {
            handle_stale_tip();
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

        // Stale tip detection during block download
        if (has_stale_tip()) {
            handle_stale_tip();
        }
    }
}

// ============================================================================
// finish_sync — transition to IDLE
// ============================================================================

void SyncManager::finish_sync() {
    state_ = State::DONE;

    int64_t elapsed = GetTime() - sync_start_time_;

    fprintf(stderr, "SyncManager: IBD complete, chain height %lu "
            "(%lu blocks in %ld seconds",
            static_cast<unsigned long>(chain_.height()),
            static_cast<unsigned long>(blocks_applied_),
            static_cast<long>(elapsed));

    if (elapsed > 0 && blocks_applied_ > 0) {
        double bps = static_cast<double>(blocks_applied_) / static_cast<double>(elapsed);
        fprintf(stderr, ", %.1f blocks/sec", bps);
    }
    fprintf(stderr, ")\n");

    inflight_.clear();
    download_buffer_.clear();
    peer_scores_.clear();

    state_ = State::IDLE;
}

// ============================================================================
// get_progress — sync progress with ETA
// ============================================================================

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
        p.blocks_per_second = 0.0;
        p.eta_seconds = 0;
        p.status_string = "Synced";
        return p;
    }

    p.headers_downloaded = headers_received_;
    p.headers_total = header_sync_target_;

    int64_t now = GetTime();
    int64_t elapsed = now - sync_start_time_;

    if (state_ == State::HEADERS) {
        p.blocks_downloaded = chain_.height();
        p.blocks_total = header_sync_target_;
        if (p.headers_total > 0) {
            p.percentage = (static_cast<double>(p.headers_downloaded)
                            / static_cast<double>(p.headers_total)) * 50.0;
        }
        p.blocks_per_second = 0.0;

        // ETA based on header download rate
        if (elapsed > 0 && headers_received_ > 0) {
            double headers_per_sec = static_cast<double>(headers_received_) /
                                     static_cast<double>(elapsed);
            if (headers_per_sec > 0) {
                uint64_t remaining = header_sync_target_ - headers_received_;
                p.eta_seconds = static_cast<int64_t>(
                    static_cast<double>(remaining) / headers_per_sec);
                // Rough estimate: block download will take ~2x the header time
                p.eta_seconds *= 3;
            }
        }

        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "Downloading headers: %lu/%lu (%.1f%%)",
                      static_cast<unsigned long>(p.headers_downloaded),
                      static_cast<unsigned long>(p.headers_total),
                      p.percentage);
        p.status_string = buf;
    } else {
        p.blocks_downloaded = next_apply_height_ > 0 ? next_apply_height_ - 1 : 0;
        p.blocks_total = blocks_download_target_;

        double header_pct = 50.0;
        double block_pct = 0.0;
        if (p.blocks_total > 0) {
            block_pct = (static_cast<double>(blocks_applied_)
                         / static_cast<double>(p.blocks_total)) * 50.0;
        }
        p.percentage = header_pct + block_pct;

        // Blocks per second
        if (elapsed > 0 && blocks_applied_ > 0) {
            p.blocks_per_second = static_cast<double>(blocks_applied_) /
                                  static_cast<double>(elapsed);
        }

        // ETA
        if (p.blocks_per_second > 0.01) {
            uint64_t remaining = blocks_download_target_ - (next_apply_height_ - 1);
            p.eta_seconds = static_cast<int64_t>(
                static_cast<double>(remaining) / p.blocks_per_second);
        }

        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "Downloading blocks: %lu/%lu (%.1f%%, %.1f blk/s, ETA %ld min)",
                      static_cast<unsigned long>(p.blocks_downloaded),
                      static_cast<unsigned long>(p.blocks_total),
                      p.percentage,
                      p.blocks_per_second,
                      static_cast<long>(p.eta_seconds / 60));
        p.status_string = buf;
    }

    return p;
}

// ============================================================================
// Assume-valid helpers
// ============================================================================

bool SyncManager::is_assume_valid_block(const uint256& hash) const {
    return !assume_valid_hash_.is_null() && hash == assume_valid_hash_;
}

bool SyncManager::past_assume_valid() const {
    if (!assume_valid_found_) return false;
    return chain_.height() > assume_valid_height_;
}

// ============================================================================
// Stale tip detection
// ============================================================================

bool SyncManager::has_stale_tip() const {
    if (state_ == State::IDLE) return false;
    int64_t now = GetTime();
    return (now - last_tip_change_time_) > STALE_TIP_THRESHOLD;
}

void SyncManager::handle_stale_tip() {
    fprintf(stderr, "SyncManager: stale tip detected (no progress for %ld seconds)\n",
            static_cast<long>(GetTime() - last_tip_change_time_));

    // Try to find a different peer with a higher chain
    auto peers = net_.get_peers();
    Peer* best_peer = nullptr;
    uint64_t current_height = chain_.height();

    for (Peer* p : peers) {
        if (p->state() != PeerState::HANDSHAKE_DONE) continue;
        if (p->should_ban()) continue;
        if (p->id() == header_sync_peer_) continue;  // Skip the stalling peer
        if (p->start_height() <= current_height) continue;

        if (!best_peer || p->start_height() > best_peer->start_height()) {
            best_peer = p;
        }
    }

    if (best_peer) {
        fprintf(stderr, "SyncManager: switching to peer %lu (height %lu) "
                "for stale tip recovery\n",
                static_cast<unsigned long>(best_peer->id()),
                static_cast<unsigned long>(best_peer->start_height()));

        header_sync_peer_ = best_peer->id();
        header_sync_target_ = best_peer->start_height();
        last_tip_change_time_ = GetTime();

        if (state_ == State::HEADERS) {
            std::vector<uint256> locator = build_locator();
            send_getheaders(*best_peer, locator);
        } else if (state_ == State::BLOCKS) {
            // Re-request all inflight blocks from the new peer
            for (auto& [height, req] : inflight_) {
                req.peer_id = best_peer->id();
                req.request_time = GetTime();
                send_getdata_block(*best_peer, req.hash);
            }
        }
    } else {
        // No alternative peers — add misbehavior to current sync peer
        // and wait for new peers to connect
        for (Peer* p : peers) {
            if (p->id() == header_sync_peer_) {
                p->add_misbehavior(10);
                break;
            }
        }
        last_tip_change_time_ = GetTime();  // Reset to avoid spam
    }
}

void SyncManager::reset_sync() {
    std::lock_guard<std::mutex> lock(mutex_);

    state_ = State::IDLE;
    inflight_.clear();
    download_buffer_.clear();
    peer_scores_.clear();
    header_requests_.clear();
    blocks_applied_ = 0;

    fprintf(stderr, "SyncManager: sync reset\n");
}

// ============================================================================
// is_near_tip — within 24 hours of current time
// ============================================================================

bool SyncManager::is_near_tip() const {
    CBlockIndex* tip = chain_.tip();
    if (!tip) return false;

    int64_t now = GetTime();
    int64_t tip_time = tip->timestamp;
    return (now - tip_time) < NEAR_TIP_THRESHOLD;
}

// ============================================================================
// update_peer_score — track per-peer download performance
// ============================================================================

void SyncManager::update_peer_score(uint64_t peer_id, int64_t delivery_time,
                                     uint64_t bytes) {
    auto& ps = peer_scores_[peer_id];
    ps.blocks_delivered++;
    ps.bytes_delivered += bytes;
    ps.total_delivery_time += delivery_time;
}

// ============================================================================
// log_progress — detailed progress with ETA
// ============================================================================

void SyncManager::log_progress() {
    int64_t now = GetTime();
    int64_t elapsed = now - sync_start_time_;

    double bps = 0.0;
    if (elapsed > 0 && blocks_applied_ > 0) {
        bps = static_cast<double>(blocks_applied_) / static_cast<double>(elapsed);
    }

    uint64_t remaining = 0;
    if (blocks_download_target_ >= next_apply_height_) {
        remaining = blocks_download_target_ - next_apply_height_ + 1;
    }

    int64_t eta_seconds = 0;
    if (bps > 0.01) {
        eta_seconds = static_cast<int64_t>(static_cast<double>(remaining) / bps);
    }

    double pct = 0.0;
    if (blocks_download_target_ > 0) {
        pct = (static_cast<double>(blocks_applied_) /
               static_cast<double>(blocks_download_target_)) * 100.0;
    }

    fprintf(stderr, "SyncManager: block %lu / %lu (%.1f%%) "
            "%.1f blk/s, ETA %ld min, inflight: %zu, buffered: %zu\n",
            static_cast<unsigned long>(next_apply_height_ > 0 ? next_apply_height_ - 1 : 0),
            static_cast<unsigned long>(blocks_download_target_),
            pct,
            bps,
            static_cast<long>(eta_seconds / 60),
            inflight_.size(),
            download_buffer_.size());
}

// ============================================================================
// Wire protocol helpers
// ============================================================================

void SyncManager::send_getheaders(Peer& peer,
                                   const std::vector<uint256>& locator) {
    DataWriter w;
    w.write_compact_size(locator.size());
    for (const auto& hash : locator) {
        w.write_bytes(hash.data(), 32);
    }

    uint256 zero;
    zero.set_null();
    w.write_bytes(zero.data(), 32);

    std::vector<uint8_t> msg = build_message(
        net_.magic(), NetCmd::GETHEADERS, w.data());
    net_.send_to(peer, msg);

    // Update synced_headers on peer
    peer.set_synced_headers(headers_received_);
}

void SyncManager::send_getdata_block(Peer& peer, const uint256& block_hash) {
    DataWriter w;
    w.write_compact_size(1);
    w.write_u32_le(INV_BLOCK);
    w.write_bytes(block_hash.data(), 32);

    std::vector<uint8_t> msg = build_message(
        net_.magic(), NetCmd::GETDATA, w.data());
    net_.send_to(peer, msg);

    // Track the request on the peer
    peer.add_pending_request(block_hash, INV_BLOCK, GetTime());
}

} // namespace flow
