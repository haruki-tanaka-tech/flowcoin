// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// In-process RandomX miner for FlowCoin.
//
// The Miner runs a pool of CPU worker threads; each thread owns a RandomX VM
// (obtained via thread_local state in consensus::ComputePowHash) and scans a
// disjoint stripe of the nonce space. When any worker finds a nonce whose
// RandomX(header, seed) is <= target, the block is signed with the miner's
// Ed25519 key and submitted via BlockSubmitter.
//
// Mining flow:
//   1. Fetch a block template (BlockAssembler) for the current chain tip.
//   2. Resolve the RandomX seed (block hash at rx_seed_height(child_height)).
//   3. Distribute the nonce space across N worker threads; each one hashes
//      RandomX(header_bytes, seed) and compares against target.
//   4. On success, sign the header with Ed25519 and submit the block.

#ifndef FLOWCOIN_MINING_MINER_H
#define FLOWCOIN_MINING_MINER_H

#include "mining/blocktemplate.h"
#include "mining/submitblock.h"
#include "primitives/block.h"
#include "util/types.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace flow {

class ChainState;
class Mempool;
class Wallet;

// ---------------------------------------------------------------------------
// MinerConfig -- runtime configuration for the Miner
// ---------------------------------------------------------------------------

struct MinerConfig {
    /// Miner's Ed25519 public key (32 bytes) — written into the block header.
    std::array<uint8_t, 32> miner_pubkey{};

    /// Miner's Ed25519 private key (64 bytes: 32 seed + 32 public) — used
    /// to sign the unsigned header.
    std::array<uint8_t, 64> miner_privkey{};

    /// Optional bech32m coinbase address. If empty, the reward goes to a
    /// P2PKH output derived from miner_pubkey (via the wallet, if any).
    std::string coinbase_address;

    /// Number of worker threads. 0 is interpreted as "one thread".
    size_t num_threads = 1;

    /// Attempts per stats update within a single search_nonce call.
    uint32_t progress_batch = 256;

    /// Continue mining after a block is found (false = mine exactly one).
    bool continuous = true;

    // --- Callbacks (optional) ---

    std::function<void(const CBlock& block)>                  on_block_found;
    std::function<void(const std::string& message)>           on_status;
    std::function<void(double hashrate, uint64_t tries)>      on_progress;
};

// ---------------------------------------------------------------------------
// MiningStats -- cumulative runtime statistics
// ---------------------------------------------------------------------------

struct MiningStats {
    uint64_t blocks_found      = 0;
    uint64_t blocks_accepted   = 0;
    uint64_t blocks_rejected   = 0;
    uint64_t total_nonces_tried = 0;
    double   total_search_time_s = 0.0;
    double   hashrate          = 0.0;   //!< Last measured H/s (aggregate across threads)
    int64_t  last_block_time   = 0;

    std::string to_string() const;
};

// ---------------------------------------------------------------------------
// NonceSearchResult -- outcome of a single search_nonce invocation
// ---------------------------------------------------------------------------

struct NonceSearchResult {
    bool     found         = false;
    uint32_t nonce         = 0;
    uint256  pow_hash;              //!< RandomX hash at the winning nonce
    uint64_t nonces_tried  = 0;
    double   search_time_s = 0.0;
};

// ---------------------------------------------------------------------------
// Miner -- the in-process mining engine
// ---------------------------------------------------------------------------

class Miner {
public:
    Miner(ChainState& chain, const MinerConfig& config,
          Mempool* mempool = nullptr, Wallet* wallet = nullptr);
    ~Miner();

    /// Start the mining loop on a background thread.
    void start();

    /// Stop the mining loop. Blocks until the mining thread exits.
    void stop();

    /// Whether the mining thread is currently running.
    bool is_running() const { return running_.load(std::memory_order_relaxed); }

    /// Run one full cycle (template -> seed -> search -> sign -> submit) and
    /// return the submit result.
    SubmitResult mine_one_block();

    /// Snapshot of cumulative statistics.
    MiningStats get_stats() const;

    /// Replace the current config (takes effect at the next cycle).
    void update_config(const MinerConfig& config);

    /// Scan `[start_nonce, start_nonce + max_tries)` (mod 2^32) for a nonce
    /// such that RandomX(header[0..91], seed) <= target. Multi-threaded per
    /// `num_threads`.
    NonceSearchResult search_nonce(CBlockHeader& header, const uint256& target,
                                    const uint256& seed,
                                    uint32_t start_nonce = 0,
                                    uint32_t max_tries = 0xFFFFFFFF);

    /// Sign an unsigned header with the miner's Ed25519 key; fills miner_sig.
    bool sign_block(CBlockHeader& header);

    /// Resolve the RandomX seed for a block at the given child height, using
    /// the current chain state. Returns the zero hash if the seed ancestor
    /// is not yet in the index (pre-bootstrap, genesis, ...).
    uint256 get_seed_for_height(uint64_t child_height) const;

private:
    ChainState&     chain_;
    MinerConfig     config_;
    Mempool*        mempool_;
    Wallet*         wallet_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::thread       mining_thread_;

    mutable std::mutex config_mutex_;
    mutable std::mutex stats_mutex_;
    MiningStats        stats_;

    void mining_loop();
    SubmitResult mine_cycle();

    void update_stats(const NonceSearchResult& result, bool accepted);
    void emit_status(const std::string& message);
};

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Measure RandomX hashrate for `duration_ms` using a single thread
/// and a zero seed. Returns H/s.
double benchmark_hashrate(int duration_ms = 1000);

/// Format a hashrate in H/s as a human-readable string ("1.23 MH/s").
std::string format_hashrate(double hashes_per_second);

/// Expected time (seconds) to find a block at the given compact-nbits target
/// and aggregate hashrate. Returns +∞ for zero hashrate.
double estimate_block_time(uint32_t nbits, double hashrate);

} // namespace flow

#endif // FLOWCOIN_MINING_MINER_H
