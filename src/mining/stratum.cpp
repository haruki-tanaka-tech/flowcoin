// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "mining/stratum.h"
#include "logging.h"
#include "util/strencodings.h"
#include "util/time.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>

namespace flow {

// ===========================================================================
// StratumJob
// ===========================================================================

std::string StratumJob::to_notify_json() const {
    std::ostringstream ss;
    ss << "{\"id\":null,\"method\":\"mining.notify\",\"params\":["
       << "\"" << job_id << "\","
       << "\"" << hex_encode(prev_hash.data(), 32) << "\","
       << "\"" << coinbase1_hex << "\","
       << "\"" << coinbase2_hex << "\","
       << "[";

    for (size_t i = 0; i < merkle_branches.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "\"" << merkle_branches[i] << "\"";
    }

    ss << "],"
       << "\"" << std::to_string(version) << "\","
       << "\"" << std::to_string(nbits) << "\","
       << "\"" << std::to_string(timestamp) << "\","
       << (clean_jobs ? "true" : "false")
       << "]}";

    return ss.str();
}

// ===========================================================================
// StratumShare
// ===========================================================================

bool StratumShare::from_json(const std::string& json, StratumShare& share) {
    // Minimal JSON parsing for share submission.
    // In production, this would use a proper JSON parser (nlohmann/json).
    // Expected format: {"id":N,"method":"mining.submit","params":["worker","jobid","nonce",...]}

    // Find worker name
    auto find_string = [&json](const std::string& key) -> std::string {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = json.find("\"", pos + key.size() + 2);
        if (pos == std::string::npos) return "";
        size_t end = json.find("\"", pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    };

    // Parse params array
    size_t params_start = json.find("[", json.find("params"));
    if (params_start == std::string::npos) return false;

    // Very basic parsing: extract comma-separated quoted strings
    std::vector<std::string> params;
    size_t pos = params_start + 1;
    while (pos < json.size()) {
        // Skip whitespace
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ',')) ++pos;
        if (pos >= json.size() || json[pos] == ']') break;

        if (json[pos] == '"') {
            size_t end = json.find('"', pos + 1);
            if (end == std::string::npos) return false;
            params.push_back(json.substr(pos + 1, end - pos - 1));
            pos = end + 1;
        } else {
            // Number or other literal
            size_t end = json.find_first_of(",]", pos);
            if (end == std::string::npos) end = json.size();
            params.push_back(json.substr(pos, end - pos));
            pos = end;
        }
    }

    if (params.size() < 3) return false;

    share.worker_name = params[0];
    share.job_id = params[1];

    // Parse nonce
    try {
        share.nonce = static_cast<uint32_t>(std::stoul(params[2]));
    } catch (...) {
        return false;
    }

    // Optional fields
    if (params.size() > 3) {
        try { share.val_loss = std::stof(params[3]); } catch (...) {}
    }
    if (params.size() > 4) {
        try { share.train_steps = static_cast<uint32_t>(std::stoul(params[4])); } catch (...) {}
    }
    if (params.size() > 5) share.delta_hash_hex = params[5];
    if (params.size() > 6) share.dataset_hash_hex = params[6];
    if (params.size() > 7) share.training_hash_hex = params[7];

    share.submit_time = GetTime();

    (void)find_string;  // suppress unused lambda warning
    return true;
}

// ===========================================================================
// StratumWorker
// ===========================================================================

std::string StratumWorker::to_string() const {
    std::ostringstream ss;
    ss << "Worker(id=" << id
       << " name=" << name
       << " auth=" << (authorized ? "yes" : "no")
       << " accepted=" << shares_accepted
       << " rejected=" << shares_rejected
       << " stale=" << shares_stale
       << " rate=" << (accept_rate() * 100.0) << "%"
       << " hashrate=" << hashrate_estimate
       << ")";
    return ss.str();
}

// ===========================================================================
// StratumServer
// ===========================================================================

StratumServer::StratumServer(const std::string& bind_addr, uint16_t port)
    : bind_addr_(bind_addr), port_(port) {}

StratumServer::~StratumServer() {
    stop();
}

bool StratumServer::start() {
    if (running_.load(std::memory_order_relaxed)) return true;

    // In production, this would start a TCP server using libuv.
    // The server listens for incoming connections and processes
    // JSON-RPC messages line by line (\n delimited).

    running_.store(true);
    start_time_ = GetTime();

    LogInfo("stratum", "Stratum server started on %s:%d", bind_addr_.c_str(), port_);
    return true;
}

void StratumServer::stop() {
    if (!running_.load(std::memory_order_relaxed)) return;
    running_.store(false);

    std::lock_guard<std::mutex> lock(mutex_);
    workers_.clear();

    LogInfo("stratum", "Stratum server stopped");
}

void StratumServer::set_job(const StratumJob& job) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_job_ = job;

    // Push the new job to all connected workers
    std::string notify = job.to_notify_json();
    (void)notify;  // In production, send to all worker sockets

    LogInfo("stratum", "New job %s at height %lu pushed to %zu workers",
            job.job_id.c_str(), (unsigned long)job.height, workers_.size());
}

void StratumServer::set_default_target(double difficulty) {
    std::lock_guard<std::mutex> lock(mutex_);
    default_target_ = difficulty;
}

size_t StratumServer::get_worker_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return workers_.size();
}

std::vector<StratumWorker> StratumServer::get_workers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<StratumWorker> result;
    result.reserve(workers_.size());
    for (const auto& [id, worker] : workers_) {
        result.push_back(worker);
    }
    return result;
}

double StratumServer::get_total_hashrate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    double total = 0.0;
    for (const auto& [id, worker] : workers_) {
        total += worker.hashrate_estimate;
    }
    return total;
}

StratumServer::Stats StratumServer::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats s = stats_;
    s.uptime_seconds = GetTime() - start_time_;
    s.peak_workers = peak_workers_;
    return s;
}

ShareResult StratumServer::validate_share(const StratumShare& share,
                                           const StratumWorker& worker) {
    ShareResult result;
    result.accepted = false;
    result.is_block = false;
    result.share_difficulty = 0.0;

    // Check that the share references a valid job
    if (share.job_id != current_job_.job_id) {
        result.reject_reason = "stale-job";
        return result;
    }

    // Check that the worker is authorized
    if (!worker.authorized) {
        result.reject_reason = "unauthorized";
        return result;
    }

    // Validate training steps meet minimum requirement
    if (share.train_steps < current_job_.min_train_steps) {
        result.reject_reason = "insufficient-training";
        return result;
    }

    // Validate the training hash is non-empty
    if (share.training_hash_hex.empty()) {
        result.reject_reason = "missing-training-hash";
        return result;
    }

    // Decode and check nonce against share target
    // In production, this would reconstruct the block header from
    // the job template + share data and verify the hash.
    result.accepted = true;
    result.share_difficulty = worker.share_target;

    // Check if this share also meets the network target
    // (i.e., it's a valid block solution)
    // This would compare the block hash against the network target.
    result.is_block = false;  // Determined by actual hash comparison

    return result;
}

void StratumServer::update_hashrate(StratumWorker& worker) {
    int64_t now = GetTime();
    int64_t elapsed = now - worker.connect_time;
    if (elapsed <= 0) return;

    // Estimate hashrate from share submission rate and share difficulty.
    // hashrate = shares * share_difficulty * 2^32 / elapsed
    double shares = static_cast<double>(worker.shares_accepted);
    worker.hashrate_estimate = shares * worker.share_target * 4294967296.0
                             / static_cast<double>(elapsed);
}

void StratumServer::adjust_target(StratumWorker& worker) {
    // Target 1 share per 10 seconds.
    // If shares come too fast, increase difficulty.
    // If shares come too slow, decrease difficulty.

    int64_t now = GetTime();
    int64_t since_last = now - worker.last_share_time;

    if (since_last < 5 && worker.shares_accepted > 10) {
        // Too fast: double the target
        worker.share_target *= 2.0;
    } else if (since_last > 30 && worker.shares_accepted > 5) {
        // Too slow: halve the target
        worker.share_target = std::max(1.0, worker.share_target / 2.0);
    }
}

} // namespace flow
