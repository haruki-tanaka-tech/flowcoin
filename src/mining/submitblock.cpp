// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "mining/submitblock.h"
#include "chain/chainstate.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "hash/keccak.h"
#include "logging.h"
#include "util/serialize.h"
#include "util/strencodings.h"
#include "util/time.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace flow {

// ===========================================================================
// SubmitResult
// ===========================================================================

std::string SubmitResult::to_string() const {
    std::ostringstream ss;
    if (accepted) {
        ss << "Block accepted at height " << height
           << " hash=" << hex_encode_reverse<32>(block_hash.data())
           << " (" << processing_time_us << " us)";
    } else {
        ss << "Block rejected at height " << height
           << " hash=" << hex_encode_reverse<32>(block_hash.data())
           << " reason=" << reject_reason;
    }
    return ss.str();
}

// ===========================================================================
// BlockSubmitter
// ===========================================================================

BlockSubmitter::BlockSubmitter(ChainState& chain, NetManager* net, Mempool* mempool)
    : chain_(chain), net_(net), mempool_(mempool) {}

// ---------------------------------------------------------------------------
// submit -- local miner submission
// ---------------------------------------------------------------------------

SubmitResult BlockSubmitter::submit(const CBlock& block) {
    return validate_and_connect(block);
}

// ---------------------------------------------------------------------------
// submit_hex -- from RPC
// ---------------------------------------------------------------------------

SubmitResult BlockSubmitter::submit_hex(const std::string& hex_block) {
    SubmitResult result;

    // Decode hex
    auto raw = hex_decode(hex_block);
    if (raw.empty()) {
        result.accepted = false;
        result.reject_reason = "invalid-hex";
        result.height = 0;
        result.processing_time_us = 0;
        return result;
    }

    return submit_raw(raw);
}

// ---------------------------------------------------------------------------
// submit_raw -- from raw bytes
// ---------------------------------------------------------------------------

SubmitResult BlockSubmitter::submit_raw(const std::vector<uint8_t>& raw_block) {
    SubmitResult result;

    CBlock block;
    if (!block.deserialize(raw_block)) {
        result.accepted = false;
        result.reject_reason = "deserialization-failed";
        result.height = 0;
        result.processing_time_us = 0;
        return result;
    }

    return validate_and_connect(block);
}

// ---------------------------------------------------------------------------
// process_network_block -- from a peer
// ---------------------------------------------------------------------------

SubmitResult BlockSubmitter::process_network_block(const CBlock& block, uint64_t peer_id) {
    SubmitResult result;
    result.block_hash = block.get_hash();
    result.height = block.height;

    // Check for duplicate
    if (is_recently_seen(result.block_hash)) {
        result.accepted = false;
        result.reject_reason = "duplicate";
        result.processing_time_us = 0;
        return result;
    }

    // Rate limiting
    if (!check_rate_limit(peer_id)) {
        result.accepted = false;
        result.reject_reason = "rate-limited";
        result.processing_time_us = 0;
        LogWarn("mining", "Rate-limited block from peer %lu at height %lu",
                (unsigned long)peer_id, (unsigned long)block.height);
        return result;
    }

    // Mark as seen
    mark_seen(result.block_hash);

    // Validate and connect
    result = validate_and_connect(block);

    // Record peer timing
    if (result.accepted) {
        record_peer_block(peer_id);
    }

    return result;
}

// ---------------------------------------------------------------------------
// validate_and_connect -- core logic
// ---------------------------------------------------------------------------

SubmitResult BlockSubmitter::validate_and_connect(const CBlock& block) {
    SubmitResult result;
    result.block_hash = block.get_hash();
    result.height = block.height;

    int64_t start_us = GetMonotonicMicros();

    consensus::ValidationState vstate;
    if (chain_.accept_block(block, vstate)) {
        result.accepted = true;
        result.reject_reason.clear();
        result.processing_time_us = GetMonotonicMicros() - start_us;

        ++blocks_accepted_;
        last_accepted_hash_ = result.block_hash;
        last_accepted_time_ = GetTime();

        LogInfo("mining", "Block accepted at height %lu hash=%s (%ld us)",
                (unsigned long)block.height,
                hex_encode_reverse<32>(result.block_hash.data()).c_str(),
                (long)result.processing_time_us);

        // Relay to peers
        if (relay_enabled_) {
            relay_block(block);
        }

        // Update mempool
        if (mempool_update_enabled_) {
            update_mempool(block);
        }
    } else {
        result.accepted = false;
        result.reject_reason = vstate.to_string();
        result.processing_time_us = GetMonotonicMicros() - start_us;

        ++blocks_rejected_;

        LogWarn("mining", "Block rejected at height %lu hash=%s: %s",
                (unsigned long)block.height,
                hex_encode_reverse<32>(result.block_hash.data()).c_str(),
                result.reject_reason.c_str());
    }

    return result;
}

// ---------------------------------------------------------------------------
// relay_block
// ---------------------------------------------------------------------------

void BlockSubmitter::relay_block(const CBlock& block) {
    if (!net_) return;

    // The NetManager handles broadcasting to all connected peers via inv messages.
    // Peers that want the block will request it via getdata.
    uint256 block_hash = block.get_hash();
    net_->broadcast_block(block_hash);

    LogDebug("mining", "Relayed block at height %lu to peers",
             (unsigned long)block.height);
}

// ---------------------------------------------------------------------------
// update_mempool
// ---------------------------------------------------------------------------

void BlockSubmitter::update_mempool(const CBlock& block) {
    if (!mempool_) return;

    // Use the mempool's built-in method to remove block transactions
    // and any conflicting mempool transactions.
    if (block.vtx.size() > 1) {
        mempool_->remove_for_block(block.vtx);
        LogDebug("mining", "Mempool updated after block at height %lu",
                 (unsigned long)block.height);
    }
}

// ---------------------------------------------------------------------------
// Rate limiting helpers
// ---------------------------------------------------------------------------

bool BlockSubmitter::check_rate_limit(uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(rate_mutex_);

    int64_t now = GetTime();
    auto it = last_block_time_.find(peer_id);
    if (it != last_block_time_.end()) {
        if (now - it->second < min_peer_block_interval_) {
            return false;  // Too soon
        }
    }
    return true;
}

void BlockSubmitter::record_peer_block(uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(rate_mutex_);
    last_block_time_[peer_id] = GetTime();

    // Prune old entries (peers we haven't heard from in an hour)
    int64_t cutoff = GetTime() - 3600;
    for (auto it = last_block_time_.begin(); it != last_block_time_.end(); ) {
        if (it->second < cutoff) {
            it = last_block_time_.erase(it);
        } else {
            ++it;
        }
    }
}

// ---------------------------------------------------------------------------
// Duplicate detection helpers
// ---------------------------------------------------------------------------

bool BlockSubmitter::is_recently_seen(const uint256& hash) {
    std::lock_guard<std::mutex> lock(seen_mutex_);
    for (const auto& h : recent_hashes_) {
        if (h == hash) return true;
    }
    return false;
}

void BlockSubmitter::mark_seen(const uint256& hash) {
    std::lock_guard<std::mutex> lock(seen_mutex_);
    recent_hashes_.push_back(hash);
    if (recent_hashes_.size() > MAX_RECENT_HASHES) {
        recent_hashes_.erase(recent_hashes_.begin());
    }
}

// ---------------------------------------------------------------------------
// Getters
// ---------------------------------------------------------------------------

uint256 BlockSubmitter::get_last_accepted_hash() const {
    return last_accepted_hash_;
}

int64_t BlockSubmitter::get_last_accepted_time() const {
    return last_accepted_time_;
}

// ===========================================================================
// Free functions (backward-compatible API)
// ===========================================================================

SubmitResult submit_block(ChainState& chain, const CBlock& block) {
    BlockSubmitter submitter(chain);
    return submitter.submit(block);
}

bool deserialize_block(const std::vector<uint8_t>& data, CBlock& block) {
    return block.deserialize(data);
}

std::vector<uint8_t> serialize_block(const CBlock& block) {
    return block.serialize();
}

bool check_block_structure(const CBlock& block, std::string& error) {
    // Must have at least one transaction (coinbase)
    if (block.vtx.empty()) {
        error = "no-transactions";
        return false;
    }

    // First transaction must be coinbase
    if (!block.vtx[0].is_coinbase()) {
        error = "first-tx-not-coinbase";
        return false;
    }

    // No other transaction may be coinbase
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        if (block.vtx[i].is_coinbase()) {
            error = "multiple-coinbase";
            return false;
        }
    }

    // Check block size
    size_t block_size = block.get_block_size();
    if (block_size > consensus::MAX_BLOCK_SIZE) {
        error = "block-too-large";
        return false;
    }

    // Check each transaction for basic validity
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        if (!block.vtx[i].check_transaction()) {
            error = "invalid-tx-" + std::to_string(i);
            return false;
        }
    }

    // Check for duplicate transactions
    std::vector<uint256> txids;
    txids.reserve(block.vtx.size());
    for (const auto& tx : block.vtx) {
        uint256 txid = tx.get_txid();
        for (const auto& existing : txids) {
            if (txid == existing) {
                error = "duplicate-tx";
                return false;
            }
        }
        txids.push_back(txid);
    }

    // Verify merkle root
    if (!block.verify_merkle_root()) {
        error = "bad-merkle-root";
        return false;
    }

    // Check delta size
    if (block.delta_payload.size() > consensus::MAX_DELTA_SIZE) {
        error = "delta-too-large";
        return false;
    }

    error.clear();
    return true;
}

std::string get_block_hash_hex(const CBlock& block) {
    return block.get_hash_hex();
}

} // namespace flow
