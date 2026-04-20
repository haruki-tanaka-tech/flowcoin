// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// In-process RandomX miner — CPU thread pool, one VM per thread (thread_local
// inside consensus::ComputePowHash), nonce space partitioned by thread id.

#include "mining/miner.h"
#include "mining/submitblock.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "consensus/difficulty.h"
#include "consensus/params.h"
#include "consensus/pow.h"
#include "crypto/sign.h"
#include "logging.h"
#include "util/arith_uint256.h"
#include "util/random.h"
#include "util/time.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <sstream>
#include <thread>
#include <vector>

namespace flow {

// ===========================================================================
// Target decoding -- produce a big-endian uint256 suitable for direct
// lexicographic comparison against the raw RandomX hash output.
// ===========================================================================

namespace {

bool decode_target_be(uint32_t nbits, uint256& target_be) {
    arith_uint256 arith;
    if (!consensus::derive_target(nbits, arith)) return false;
    uint256 le = ArithToUint256(arith);
    for (int i = 0; i < 32; ++i) target_be[i] = le[31 - i];
    return true;
}

} // anonymous namespace

// ===========================================================================
// MiningStats
// ===========================================================================

std::string MiningStats::to_string() const {
    std::ostringstream ss;
    ss << "MiningStats("
       << "found="     << blocks_found
       << " accepted=" << blocks_accepted
       << " rejected=" << blocks_rejected
       << " nonces="   << total_nonces_tried
       << " hashrate=" << format_hashrate(hashrate)
       << ")";
    return ss.str();
}

// ===========================================================================
// Miner -- construction / lifecycle
// ===========================================================================

Miner::Miner(ChainState& chain, const MinerConfig& config,
             Mempool* mempool, Wallet* wallet)
    : chain_(chain), config_(config), mempool_(mempool), wallet_(wallet) {}

Miner::~Miner() {
    stop();
}

void Miner::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) return;

    stop_requested_.store(false);
    mining_thread_ = std::thread([this]() { mining_loop(); });

    emit_status("Mining started");
}

void Miner::stop() {
    if (!running_.load(std::memory_order_relaxed)) return;

    stop_requested_.store(true);
    if (mining_thread_.joinable()) mining_thread_.join();
    running_.store(false);

    emit_status("Mining stopped");
}

// ===========================================================================
// Mining loop
// ===========================================================================

void Miner::mining_loop() {
    LogInfo("mining", "Mining loop started");

    while (!stop_requested_.load(std::memory_order_relaxed)) {
        SubmitResult r = mine_cycle();

        if (r.accepted) {
            emit_status("Block accepted at height " + std::to_string(r.height));
        } else if (!r.reject_reason.empty()) {
            emit_status("Block rejected: " + r.reject_reason);
        }

        MinerConfig cfg_snap;
        { std::lock_guard<std::mutex> l(config_mutex_); cfg_snap = config_; }
        if (!cfg_snap.continuous) break;
    }

    LogInfo("mining", "Mining loop exited");
    running_.store(false);
}

SubmitResult Miner::mine_cycle() {
    SubmitResult result;
    result.accepted = false;

    MinerConfig cfg;
    { std::lock_guard<std::mutex> l(config_mutex_); cfg = config_; }

    // 1. Template
    BlockAssembler assembler(chain_, mempool_, wallet_);
    BlockTemplate tmpl = cfg.coinbase_address.empty()
        ? assembler.create_template(cfg.miner_pubkey)
        : assembler.create_template(cfg.coinbase_address);

    emit_status("Template for height " + std::to_string(tmpl.header.height)
                + " (" + std::to_string(tmpl.tx_count()) + " txs)");

    // 2. Assemble block and stamp miner identity
    CBlock block = tmpl.assemble();
    std::memcpy(block.miner_pubkey.data(), cfg.miner_pubkey.data(), 32);
    block.merkle_root = block.compute_merkle_root();

    // 3. Resolve RandomX seed and decoded target
    uint256 seed = get_seed_for_height(block.height);

    uint256 target_be;
    if (!decode_target_be(block.nbits, target_be)) {
        result.reject_reason = "bad-nbits";
        result.height = block.height;
        return result;
    }

    // 4. Scan nonce space
    NonceSearchResult ns = search_nonce(block, target_be, seed);
    if (!ns.found) {
        result.reject_reason = "nonce-exhausted";
        result.height = block.height;
        return result;
    }

    double rate = ns.search_time_s > 0.0
        ? static_cast<double>(ns.nonces_tried) / ns.search_time_s
        : 0.0;
    emit_status("Nonce " + std::to_string(ns.nonce)
                + " after " + std::to_string(ns.nonces_tried) + " tries"
                + " (" + format_hashrate(rate) + ")");

    // 5. Sign
    if (!sign_block(block)) {
        result.reject_reason = "signing-failed";
        result.height = block.height;
        return result;
    }

    // 6. Submit
    BlockSubmitter submitter(chain_);
    result = submitter.submit(block);

    update_stats(ns, result.accepted);

    if (result.accepted && cfg.on_block_found) cfg.on_block_found(block);

    return result;
}

SubmitResult Miner::mine_one_block() {
    return mine_cycle();
}

MiningStats Miner::get_stats() const {
    std::lock_guard<std::mutex> l(stats_mutex_);
    return stats_;
}

void Miner::update_config(const MinerConfig& config) {
    std::lock_guard<std::mutex> l(config_mutex_);
    config_ = config;
}

// ===========================================================================
// search_nonce -- multi-threaded scan with thread-local RandomX VMs
// ===========================================================================

NonceSearchResult Miner::search_nonce(CBlockHeader& header,
                                       const uint256& target_be,
                                       const uint256& seed,
                                       uint32_t start_nonce,
                                       uint32_t max_tries) {
    MinerConfig cfg_snap;
    { std::lock_guard<std::mutex> l(config_mutex_); cfg_snap = config_; }
    size_t num_threads = std::max<size_t>(1, cfg_snap.num_threads);

    auto t0 = std::chrono::steady_clock::now();

    std::atomic<bool>     found{false};
    std::atomic<uint32_t> winning_nonce{0};
    std::atomic<uint64_t> total_tried{0};
    uint256               winning_hash{};
    std::mutex            winning_mutex;

    auto worker = [&](size_t thread_id) {
        // Each thread owns a private copy of the 92-byte unsigned header so
        // writes to the nonce bytes do not race.
        std::vector<uint8_t> buf = header.get_unsigned_data();
        if (buf.size() != BLOCK_HEADER_UNSIGNED_SIZE) return;

        uint64_t local_tried = 0;
        for (uint64_t i = thread_id; i < max_tries; i += num_threads) {
            if (found.load(std::memory_order_relaxed)) break;
            if (stop_requested_.load(std::memory_order_relaxed)) break;

            uint32_t nonce = start_nonce + static_cast<uint32_t>(i);
            buf[84] = static_cast<uint8_t>(nonce);
            buf[85] = static_cast<uint8_t>(nonce >> 8);
            buf[86] = static_cast<uint8_t>(nonce >> 16);
            buf[87] = static_cast<uint8_t>(nonce >> 24);

            uint256 pow_hash = consensus::ComputePowHash(
                buf.data(), buf.size(), seed);
            ++local_tried;

            if (pow_hash <= target_be) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    winning_nonce.store(nonce);
                    std::lock_guard<std::mutex> l(winning_mutex);
                    winning_hash = pow_hash;
                }
                break;
            }
        }
        total_tried.fetch_add(local_tried, std::memory_order_relaxed);
    };

    std::vector<std::thread> workers;
    workers.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) workers.emplace_back(worker, i);
    for (auto& t : workers) t.join();

    auto t1 = std::chrono::steady_clock::now();

    NonceSearchResult r;
    r.found         = found.load();
    r.nonce         = winning_nonce.load();
    r.nonces_tried  = total_tried.load();
    r.search_time_s = std::chrono::duration<double>(t1 - t0).count();
    if (r.found) {
        r.pow_hash = winning_hash;
        header.nonce = r.nonce;
    }
    return r;
}

// ===========================================================================
// sign_block
// ===========================================================================

bool Miner::sign_block(CBlockHeader& header) {
    MinerConfig cfg;
    { std::lock_guard<std::mutex> l(config_mutex_); cfg = config_; }

    auto data = header.get_unsigned_data();
    auto sig = flow::ed25519_sign(
        data.data(), data.size(),
        cfg.miner_privkey.data(),
        cfg.miner_pubkey.data());

    std::memcpy(header.miner_sig.data(), sig.data(), 64);
    return true;
}

// ===========================================================================
// get_seed_for_height
// ===========================================================================

uint256 Miner::get_seed_for_height(uint64_t child_height) const {
    uint64_t seed_h = consensus::rx_seed_height(child_height);
    const CBlockIndex* node = chain_.tip();
    while (node && node->height > seed_h) node = node->prev;
    if (node && node->height == seed_h) return node->hash;
    return uint256{};
}

// ===========================================================================
// Internal bookkeeping
// ===========================================================================

void Miner::update_stats(const NonceSearchResult& ns, bool accepted) {
    std::lock_guard<std::mutex> l(stats_mutex_);

    stats_.blocks_found++;
    if (accepted) stats_.blocks_accepted++; else stats_.blocks_rejected++;
    stats_.total_nonces_tried += ns.nonces_tried;
    stats_.total_search_time_s += ns.search_time_s;
    stats_.last_block_time = GetTime();

    if (ns.search_time_s > 0.0) {
        stats_.hashrate = static_cast<double>(ns.nonces_tried) / ns.search_time_s;
    }
}

void Miner::emit_status(const std::string& message) {
    LogInfo("mining", "%s", message.c_str());

    MinerConfig cfg;
    { std::lock_guard<std::mutex> l(config_mutex_); cfg = config_; }
    if (cfg.on_status) cfg.on_status(message);
}

// ===========================================================================
// Free functions
// ===========================================================================

double benchmark_hashrate(int duration_ms) {
    // Use a fresh 92-byte buffer and a zero seed. ComputePowHash will create
    // a cache + thread-local VM on first call; include cache init time in
    // the measurement window for an honest end-to-end number.
    std::vector<uint8_t> buf(BLOCK_HEADER_UNSIGNED_SIZE);
    GetRandBytes(buf.data(), buf.size());
    uint256 seed{};

    auto start = std::chrono::steady_clock::now();
    auto deadline = start + std::chrono::milliseconds(duration_ms);

    uint64_t count = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        uint32_t nonce = static_cast<uint32_t>(count);
        std::memcpy(buf.data() + 84, &nonce, 4);
        (void)consensus::ComputePowHash(buf.data(), buf.size(), seed);
        ++count;
    }

    auto end = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();
    return elapsed > 0.0 ? static_cast<double>(count) / elapsed : 0.0;
}

std::string format_hashrate(double h) {
    char buf[64];
    if      (h >= 1e12) std::snprintf(buf, sizeof(buf), "%.2f TH/s", h / 1e12);
    else if (h >= 1e9)  std::snprintf(buf, sizeof(buf), "%.2f GH/s", h / 1e9);
    else if (h >= 1e6)  std::snprintf(buf, sizeof(buf), "%.2f MH/s", h / 1e6);
    else if (h >= 1e3)  std::snprintf(buf, sizeof(buf), "%.2f kH/s", h / 1e3);
    else                std::snprintf(buf, sizeof(buf), "%.2f H/s",  h);
    return std::string(buf);
}

double estimate_block_time(uint32_t nbits, double hashrate) {
    if (hashrate <= 0.0) return std::numeric_limits<double>::infinity();

    arith_uint256 target;
    target.SetCompact(nbits);
    int target_bits = target.bits();
    if (target_bits <= 0) return std::numeric_limits<double>::infinity();

    double expected_hashes = std::pow(2.0, 256 - target_bits);
    return expected_hashes / hashrate;
}

} // namespace flow
