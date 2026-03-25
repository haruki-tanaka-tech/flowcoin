// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Stratum-like protocol support for FlowCoin mining pools.
//
// FlowCoin's stratum variant differs from Bitcoin's in that miners must
// perform actual model training work rather than just hashing. The pool
// distributes training tasks and validates training proofs.
//
// Protocol messages (JSON-RPC over TCP):
//   mining.subscribe    -- Miner connects and subscribes
//   mining.authorize    -- Miner authenticates with credentials
//   mining.notify       -- Pool sends a new training job
//   mining.submit       -- Miner submits a training proof + nonce
//   mining.set_target   -- Pool adjusts the share difficulty

#ifndef FLOWCOIN_MINING_STRATUM_H
#define FLOWCOIN_MINING_STRATUM_H

#include "primitives/block.h"
#include "util/types.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace flow {

// ---------------------------------------------------------------------------
// StratumJob -- a training job distributed to miners
// ---------------------------------------------------------------------------

struct StratumJob {
    std::string job_id;                //!< Unique job identifier
    uint256 prev_hash;                 //!< Previous block hash
    uint64_t height;                   //!< Block height
    uint32_t nbits;                    //!< Difficulty target
    int64_t timestamp;                 //!< Block timestamp
    std::string coinbase1_hex;         //!< Coinbase prefix (hex)
    std::string coinbase2_hex;         //!< Coinbase suffix (hex)
    std::vector<std::string> merkle_branches; //!< Merkle branch hashes (hex)
    uint32_t version;                  //!< Block version
    bool clean_jobs;                   //!< If true, discard previous jobs

    /// Model dimensions for this job
    uint32_t d_model;
    uint32_t n_layers;
    uint32_t d_ff;
    uint32_t n_heads;
    uint32_t gru_dim;
    uint32_t n_slots;

    /// Serialize the job as a JSON notify message.
    std::string to_notify_json() const;
};

// ---------------------------------------------------------------------------
// StratumShare -- a training proof submission from a miner
// ---------------------------------------------------------------------------

struct StratumShare {
    std::string worker_name;           //!< Worker identifier
    std::string job_id;                //!< Job this share is for
    uint32_t nonce;                    //!< Mining nonce
    float val_loss;                    //!< Validation loss achieved
    uint32_t train_steps;              //!< Training steps performed (informational)
    std::string delta_hash_hex;        //!< Hash of the delta payload (hex)
    std::string dataset_hash_hex;      //!< Hash of the evaluation dataset (hex)
    std::string training_hash_hex;     //!< Combined training hash (hex)
    int64_t submit_time;               //!< When the share was submitted

    /// Parse a share from a JSON submit message.
    static bool from_json(const std::string& json, StratumShare& share);
};

// ---------------------------------------------------------------------------
// ShareResult -- outcome of share validation
// ---------------------------------------------------------------------------

struct ShareResult {
    bool accepted;                     //!< Share accepted?
    bool is_block;                     //!< Share is a valid block solution?
    std::string reject_reason;         //!< Reason for rejection
    double share_difficulty;           //!< Difficulty of this share
};

// ---------------------------------------------------------------------------
// StratumWorker -- represents a connected mining worker
// ---------------------------------------------------------------------------

struct StratumWorker {
    uint64_t id;                       //!< Internal worker ID
    std::string name;                  //!< Worker name (user.worker)
    std::string user;                  //!< Pool username
    bool authorized;                   //!< Has the worker been authorized?
    double share_target;               //!< Current share target difficulty
    int64_t connect_time;              //!< Unix timestamp of connection
    int64_t last_share_time;           //!< Timestamp of last accepted share
    uint64_t shares_accepted;          //!< Total accepted shares
    uint64_t shares_rejected;          //!< Total rejected shares
    uint64_t shares_stale;             //!< Stale shares (job expired)
    double hashrate_estimate;          //!< Estimated hashrate

    /// Get the accept rate (0.0 to 1.0).
    double accept_rate() const {
        uint64_t total = shares_accepted + shares_rejected + shares_stale;
        if (total == 0) return 0.0;
        return static_cast<double>(shares_accepted) / static_cast<double>(total);
    }

    /// Get a human-readable summary.
    std::string to_string() const;
};

// ---------------------------------------------------------------------------
// StratumServer -- mining pool server
// ---------------------------------------------------------------------------

class StratumServer {
public:
    /// Callback types for pool operators
    using AuthCallback = std::function<bool(const std::string& user,
                                             const std::string& password)>;
    using BlockFoundCallback = std::function<void(const CBlock& block)>;
    using ShareCallback = std::function<void(const StratumWorker& worker,
                                              const StratumShare& share,
                                              const ShareResult& result)>;

    /// Construct with bind address and port.
    StratumServer(const std::string& bind_addr, uint16_t port);
    ~StratumServer();

    /// Start the stratum server.
    bool start();

    /// Stop the stratum server.
    void stop();

    /// Set the current mining job (pushes to all connected workers).
    void set_job(const StratumJob& job);

    /// Set the share difficulty for new connections.
    void set_default_target(double difficulty);

    /// Set authentication callback.
    void set_auth_callback(AuthCallback cb) { auth_callback_ = std::move(cb); }

    /// Set block found callback.
    void set_block_callback(BlockFoundCallback cb) { block_callback_ = std::move(cb); }

    /// Set share callback (for logging/accounting).
    void set_share_callback(ShareCallback cb) { share_callback_ = std::move(cb); }

    /// Get the number of connected workers.
    size_t get_worker_count() const;

    /// Get all connected workers.
    std::vector<StratumWorker> get_workers() const;

    /// Get total hashrate estimate across all workers.
    double get_total_hashrate() const;

    /// Get statistics since server start.
    struct Stats {
        uint64_t total_shares_accepted;
        uint64_t total_shares_rejected;
        uint64_t total_shares_stale;
        uint64_t total_blocks_found;
        int64_t uptime_seconds;
        size_t peak_workers;
    };
    Stats get_stats() const;

    /// Check if the server is running.
    bool is_running() const { return running_.load(std::memory_order_relaxed); }

private:
    std::string bind_addr_;
    uint16_t port_;
    std::atomic<bool> running_{false};

    AuthCallback auth_callback_;
    BlockFoundCallback block_callback_;
    ShareCallback share_callback_;

    mutable std::mutex mutex_;
    std::map<uint64_t, StratumWorker> workers_;
    StratumJob current_job_;
    double default_target_ = 1.0;
    uint64_t next_worker_id_ = 1;

    Stats stats_{};
    int64_t start_time_ = 0;
    size_t peak_workers_ = 0;

    /// Validate a submitted share against the current job.
    ShareResult validate_share(const StratumShare& share, const StratumWorker& worker);

    /// Update the worker's hashrate estimate based on share submission rate.
    void update_hashrate(StratumWorker& worker);

    /// Adjust the share target for a worker based on their submission rate.
    /// Targets a steady rate of ~1 share per 10 seconds.
    void adjust_target(StratumWorker& worker);
};

} // namespace flow

#endif // FLOWCOIN_MINING_STRATUM_H
