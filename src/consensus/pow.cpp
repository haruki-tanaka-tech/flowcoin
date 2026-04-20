// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// RandomX Proof-of-Work implementation.

#include "pow.h"
#include "difficulty.h"
#include "params.h"
#include "../util/arith_uint256.h"

#include <randomx.h>

#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>

namespace flow::consensus {

// ===========================================================================
// Seed rotation
// ===========================================================================

uint64_t rx_seed_height(uint64_t height) {
    if (height <= SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG) return 0;
    return (height - SEEDHASH_EPOCH_LAG - 1) & ~(SEEDHASH_EPOCH_BLOCKS - 1);
}

// ===========================================================================
// RandomX runtime
//
// Caches and the optional dataset are reference-counted via shared_ptr so that
// thread-local VMs keep their cache alive across an epoch rotation. The global
// state holds an LRU of up to 2 caches (current + previous epoch) to absorb
// reorgs that cross an epoch boundary without re-initialising.
// ===========================================================================

namespace {

struct CacheHolder {
    randomx_cache* cache = nullptr;
    ~CacheHolder() { if (cache) randomx_release_cache(cache); }
};

struct DatasetHolder {
    randomx_dataset* dataset = nullptr;
    ~DatasetHolder() { if (dataset) randomx_release_dataset(dataset); }
};

using CachePtr = std::shared_ptr<CacheHolder>;
using DatasetPtr = std::shared_ptr<DatasetHolder>;

struct CacheSlot {
    uint256 seed;
    CachePtr holder;  // null when slot is empty
};

struct Runtime {
    std::shared_mutex mutex;
    bool configured = false;
    bool full_mem = false;
    randomx_flags flags = RANDOMX_FLAG_DEFAULT;
    DatasetPtr dataset;                   // only populated in full_mem mode
    std::array<CacheSlot, 2> slots = {};  // LRU of size 2
    size_t next_slot = 0;
};

Runtime& runtime() {
    static Runtime rt;
    return rt;
}

// Per-thread VM. Each thread creates its VM on first hash and reuses it.
// The held CachePtr keeps the cache alive if the global LRU evicts it while
// this thread is still using the VM.
struct ThreadVM {
    randomx_vm* vm = nullptr;
    CachePtr cache_ref;  // keeps the current cache alive
    uint256 seed{};
    bool has_seed = false;

    ~ThreadVM() {
        if (vm) randomx_destroy_vm(vm);
    }
};

thread_local ThreadVM tls_vm;

// Caller must NOT hold the runtime mutex. Acquires unique_lock internally.
CachePtr get_or_make_cache(const uint256& seed) {
    Runtime& rt = runtime();

    // Fast path: shared lock, check if cache already exists.
    {
        std::shared_lock rlock(rt.mutex);
        for (const auto& slot : rt.slots) {
            if (slot.holder && slot.seed == seed) {
                return slot.holder;
            }
        }
    }

    // Slow path: create under unique lock.
    std::unique_lock wlock(rt.mutex);

    // Re-check after upgrading — another thread may have created it.
    for (const auto& slot : rt.slots) {
        if (slot.holder && slot.seed == seed) {
            return slot.holder;
        }
    }

    auto holder = std::make_shared<CacheHolder>();
    holder->cache = randomx_alloc_cache(rt.flags);
    if (!holder->cache) {
        throw std::runtime_error("randomx_alloc_cache failed");
    }
    randomx_init_cache(holder->cache, seed.data(), seed.size());

    // In full-mem mode, also rebuild the dataset for the new cache.
    if (rt.full_mem) {
        auto ds = std::make_shared<DatasetHolder>();
        ds->dataset = randomx_alloc_dataset(rt.flags);
        if (!ds->dataset) {
            throw std::runtime_error("randomx_alloc_dataset failed");
        }
        unsigned long total = randomx_dataset_item_count();
        randomx_init_dataset(ds->dataset, holder->cache, 0, total);
        rt.dataset = ds;
    }

    // Evict the oldest slot.
    CacheSlot& slot = rt.slots[rt.next_slot];
    slot.seed = seed;
    slot.holder = holder;
    rt.next_slot = (rt.next_slot + 1) % rt.slots.size();

    return holder;
}

} // anonymous namespace

void ConfigureRandomX(bool full_mem, bool large_pages) {
    Runtime& rt = runtime();
    std::unique_lock wlock(rt.mutex);
    if (rt.configured) return;

    rt.full_mem = full_mem;
    rt.flags = randomx_get_flags();
    if (large_pages) rt.flags |= RANDOMX_FLAG_LARGE_PAGES;
    if (full_mem)    rt.flags |= RANDOMX_FLAG_FULL_MEM;

    rt.configured = true;
}

void WarmUpRandomX(const uint256& seed) {
    // Ensure configured with defaults (light mode, no large pages).
    {
        Runtime& rt = runtime();
        std::shared_lock rlock(rt.mutex);
        bool ok = rt.configured;
        rlock.unlock();
        if (!ok) ConfigureRandomX(false, false);
    }
    (void)get_or_make_cache(seed);
}

void ShutdownRandomX() {
    Runtime& rt = runtime();
    std::unique_lock wlock(rt.mutex);
    for (auto& slot : rt.slots) {
        slot.holder.reset();
        slot.seed = uint256{};
    }
    rt.dataset.reset();
    rt.configured = false;
    rt.next_slot = 0;
}

uint256 ComputePowHash(const uint8_t* data, size_t len, const uint256& seed) {
    Runtime& rt = runtime();

    // Lazy default configuration for verifier-only paths.
    {
        std::shared_lock rlock(rt.mutex);
        bool ok = rt.configured;
        rlock.unlock();
        if (!ok) ConfigureRandomX(false, false);
    }

    CachePtr cache = get_or_make_cache(seed);

    // Snapshot dataset pointer under shared lock (may be null in light mode).
    DatasetPtr ds;
    randomx_flags flags;
    {
        std::shared_lock rlock(rt.mutex);
        ds = rt.dataset;
        flags = rt.flags;
    }

    // Create or update this thread's VM.
    if (!tls_vm.vm) {
        tls_vm.vm = randomx_create_vm(flags, cache->cache,
                                       ds ? ds->dataset : nullptr);
        if (!tls_vm.vm) {
            throw std::runtime_error("randomx_create_vm failed");
        }
        tls_vm.cache_ref = cache;
        tls_vm.seed = seed;
        tls_vm.has_seed = true;
    } else if (!tls_vm.has_seed || tls_vm.seed != seed) {
        randomx_vm_set_cache(tls_vm.vm, cache->cache);
        if (ds && ds->dataset) {
            randomx_vm_set_dataset(tls_vm.vm, ds->dataset);
        }
        tls_vm.cache_ref = cache;
        tls_vm.seed = seed;
        tls_vm.has_seed = true;
    }

    uint256 result;
    randomx_calculate_hash(tls_vm.vm, data, len, result.data());
    return result;
}

// ===========================================================================
// PoW verification
// ===========================================================================

bool CheckProofOfWork(const CBlockHeader& header, const uint256& seed) {
    arith_uint256 target;
    if (!derive_target(header.nbits, target)) {
        return false;
    }

    auto header_bytes = header.get_unsigned_data();
    uint256 pow_hash = ComputePowHash(header_bytes.data(), header_bytes.size(),
                                       seed);

    // derive_target gives us a little-endian arith_uint256; the hash is raw
    // bytes in the same little-endian layout used for chain arithmetic, so
    // compare via ArithToUint256 with a byte-reverse to big-endian.
    uint256 target_le = ArithToUint256(target);
    uint256 target_be;
    for (int i = 0; i < 32; ++i) {
        target_be[i] = target_le[31 - i];
    }
    return pow_hash <= target_be;
}

// ===========================================================================
// Difficulty math (unchanged from Keccak era — target/nbits encoding is
// independent of the hash function used)
// ===========================================================================

arith_uint256 GetPowLimit() {
    arith_uint256 limit;
    limit.SetCompact(INITIAL_NBITS);
    return limit;
}

double GetDifficulty(uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) return 0.0;

    int shift = (nbits >> 24) & 0xff;
    double mantissa = static_cast<double>(nbits & 0x00ffffff);
    if (mantissa == 0.0) return 0.0;

    int pow_shift = (INITIAL_NBITS >> 24) & 0xff;
    double pow_mantissa = static_cast<double>(INITIAL_NBITS & 0x00ffffff);

    double difficulty = pow_mantissa / mantissa;
    int exponent_diff = pow_shift - shift;
    if (exponent_diff > 0) {
        difficulty *= std::pow(256.0, static_cast<double>(exponent_diff));
    } else if (exponent_diff < 0) {
        difficulty /= std::pow(256.0, static_cast<double>(-exponent_diff));
    }
    return difficulty;
}

bool AllowMinDifficultyBlocks(bool regtest) { return regtest; }

uint32_t GetNextWorkRequired(uint64_t parent_height, uint32_t parent_nbits,
                              int64_t parent_timestamp, int64_t first_block_time,
                              bool regtest) {
    uint64_t child_height = parent_height + 1;
    if (regtest) return INITIAL_NBITS;
    return get_next_work_required(child_height, parent_nbits,
                                   first_block_time, parent_timestamp);
}

double EstimateNetworkHashrate(double difficulty) {
    if (difficulty <= 0.0) return 0.0;
    constexpr double two_pow_32 = 4294967296.0;
    return difficulty * two_pow_32 / static_cast<double>(TARGET_BLOCK_TIME);
}

arith_uint256 GetBlockProof(uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) return arith_uint256(0);

    arith_uint256 one(1);
    arith_uint256 target_plus_one = target;
    target_plus_one += one;
    if (target_plus_one.IsNull()) return arith_uint256(0);

    arith_uint256 not_target = ~target;
    arith_uint256 work = not_target / target_plus_one;
    work += one;
    return work;
}

uint32_t DifficultyToTarget(double difficulty) {
    if (difficulty <= 0.0 || !std::isfinite(difficulty)) return INITIAL_NBITS;

    arith_uint256 pow_limit = GetPowLimit();
    if (difficulty <= 1.0) return pow_limit.GetCompact();

    int pow_shift = (INITIAL_NBITS >> 24) & 0xff;
    double pow_mantissa = static_cast<double>(INITIAL_NBITS & 0x00ffffff);
    double target_mantissa = pow_mantissa / difficulty;

    int shift = pow_shift;
    while (target_mantissa < 0x008000 && shift > 3) {
        target_mantissa *= 256.0;
        shift--;
    }
    while (target_mantissa > 0x7fffff) {
        target_mantissa /= 256.0;
        shift++;
    }

    uint32_t mantissa = static_cast<uint32_t>(target_mantissa) & 0x7fffff;
    return (static_cast<uint32_t>(shift) << 24) | mantissa;
}

std::string FormatTarget(uint32_t nbits) {
    arith_uint256 target;
    if (!derive_target(nbits, target)) return "invalid";

    std::string hex;
    hex.reserve(64);
    static const char hexchars[] = "0123456789abcdef";
    bool leading = true;

    for (int i = arith_uint256::WIDTH - 1; i >= 0; i--) {
        uint32_t limb = target.pn[i];
        for (int j = 28; j >= 0; j -= 4) {
            uint8_t nibble = (limb >> j) & 0xf;
            if (nibble == 0 && leading) continue;
            leading = false;
            hex.push_back(hexchars[nibble]);
        }
    }

    if (hex.empty()) hex = "0";
    return hex;
}

double EstimateTimeToBlock(double difficulty, double local_hashrate) {
    if (local_hashrate <= 0.0 || difficulty <= 0.0) {
        return std::numeric_limits<double>::infinity();
    }
    constexpr double two_pow_32 = 4294967296.0;
    double expected_hashes = difficulty * two_pow_32;
    return expected_hashes / local_hashrate;
}

void GetRetargetPeriod(uint64_t height, uint64_t& period_start,
                        uint64_t& period_end) {
    uint64_t period_index = height / RETARGET_INTERVAL;
    period_start = period_index * RETARGET_INTERVAL;
    period_end = period_start + RETARGET_INTERVAL - 1;
}

DifficultyProgress GetDifficultyProgress(uint64_t current_height,
                                          uint32_t current_nbits,
                                          int64_t period_start_time,
                                          int64_t current_time) {
    DifficultyProgress progress{};

    progress.current_difficulty = GetDifficulty(current_nbits);
    progress.blocks_in_period =
        static_cast<double>(current_height % RETARGET_INTERVAL);
    progress.period_progress_pct =
        (progress.blocks_in_period / static_cast<double>(RETARGET_INTERVAL)) * 100.0;
    progress.blocks_until_retarget = BlocksUntilRetarget(current_height);
    progress.estimated_hashrate = EstimateNetworkHashrate(progress.current_difficulty);

    if (period_start_time > 0 && current_time > period_start_time &&
        progress.blocks_in_period > 0) {
        int64_t elapsed = current_time - period_start_time;
        double blocks_per_second = progress.blocks_in_period /
                                   static_cast<double>(elapsed);
        double expected_timespan = static_cast<double>(RETARGET_TIMESPAN);
        double projected_timespan = static_cast<double>(RETARGET_INTERVAL) /
                                    blocks_per_second;
        progress.estimated_adjustment = expected_timespan / projected_timespan;

        double max_adj = static_cast<double>(MAX_RETARGET_FACTOR);
        if (progress.estimated_adjustment > max_adj) {
            progress.estimated_adjustment = max_adj;
        }
        if (progress.estimated_adjustment < 1.0 / max_adj) {
            progress.estimated_adjustment = 1.0 / max_adj;
        }
    } else {
        progress.estimated_adjustment = 1.0;
    }

    return progress;
}

} // namespace flow::consensus
