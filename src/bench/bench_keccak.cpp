// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Benchmarks for Keccak-256 hashing: single, double, incremental, HashWriter,
// and Merkle root computation at various transaction counts.

#include "bench.h"
#include "hash/keccak.h"
#include "hash/merkle.h"
#include "util/types.h"

#include <cstring>
#include <vector>

namespace {

// Pre-allocated data buffers
static std::vector<uint8_t> make_data(size_t len) {
    std::vector<uint8_t> buf(len);
    for (size_t i = 0; i < len; i++) {
        buf[i] = static_cast<uint8_t>(i * 0x5A + 0x13);
    }
    return buf;
}

} // namespace

namespace flow::bench {

// ===========================================================================
// Keccak-256 single hash
// ===========================================================================

BENCH(Keccak256_32B) {
    auto data = make_data(32);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256(data.data(), data.size());
        // Prevent optimization: feed result back
        data[0] = h.data()[0];
    }
}

BENCH(Keccak256_64B) {
    auto data = make_data(64);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

BENCH(Keccak256_256B) {
    auto data = make_data(256);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

BENCH(Keccak256_1KB) {
    auto data = make_data(1024);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

BENCH(Keccak256_4KB) {
    auto data = make_data(4096);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

BENCH(Keccak256_1MB) {
    auto data = make_data(1024 * 1024);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

// ===========================================================================
// Keccak-256d (double hash)
// ===========================================================================

BENCH(Keccak256d_32B) {
    auto data = make_data(32);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256d(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

BENCH(Keccak256d_1KB) {
    auto data = make_data(1024);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256d(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

// ===========================================================================
// HashWriter (serialize into hash)
// ===========================================================================

BENCH(HashWriter_SmallFields) {
    for (int i = 0; i < _iterations; i++) {
        HashWriter hw;
        hw << uint32_t(1);
        hw << uint64_t(12345678);
        hw << uint32_t(0x1f00ffff);
        hw << uint64_t(1000000);
        uint256 h = hw.GetHash();
        (void)h;
    }
}

BENCH(HashWriter_LargePayload) {
    auto data = make_data(4096);
    for (int i = 0; i < _iterations; i++) {
        HashWriter hw;
        hw << uint32_t(1);
        hw.write(data);
        uint256 h = hw.GetDoubleHash();
        (void)h;
    }
}

// ===========================================================================
// Incremental Keccak-256
// ===========================================================================

BENCH(CKeccak256_Incremental_100Chunks) {
    auto chunk = make_data(64);
    for (int i = 0; i < _iterations; i++) {
        CKeccak256 hasher;
        for (int c = 0; c < 100; c++) {
            hasher.update(chunk.data(), chunk.size());
        }
        uint256 h = hasher.finalize();
        chunk[0] = h.data()[0];
    }
}

// ===========================================================================
// Merkle root computation
// ===========================================================================

BENCH(MerkleRoot_1Tx) {
    uint256 leaf;
    std::memset(leaf.data(), 0xAB, 32);
    std::vector<uint256> leaves = {leaf};
    for (int i = 0; i < _iterations; i++) {
        uint256 root = compute_merkle_root(leaves);
        leaves[0].data()[0] = root.data()[0];
    }
}

BENCH(MerkleRoot_10Tx) {
    std::vector<uint256> leaves(10);
    for (size_t j = 0; j < leaves.size(); j++) {
        std::memset(leaves[j].data(), static_cast<int>(j + 1), 32);
    }
    for (int i = 0; i < _iterations; i++) {
        uint256 root = compute_merkle_root(leaves);
        leaves[0].data()[0] = root.data()[0];
    }
}

BENCH(MerkleRoot_100Tx) {
    std::vector<uint256> leaves(100);
    for (size_t j = 0; j < leaves.size(); j++) {
        std::memset(leaves[j].data(), static_cast<int>(j % 256), 32);
    }
    for (int i = 0; i < _iterations; i++) {
        uint256 root = compute_merkle_root(leaves);
        leaves[0].data()[0] = root.data()[0];
    }
}

BENCH(MerkleRoot_1000Tx) {
    std::vector<uint256> leaves(1000);
    for (size_t j = 0; j < leaves.size(); j++) {
        std::memset(leaves[j].data(), static_cast<int>(j % 256), 32);
    }
    for (int i = 0; i < _iterations; i++) {
        uint256 root = compute_merkle_root(leaves);
        leaves[0].data()[0] = root.data()[0];
    }
}

// ===========================================================================
// Keccak-512
// ===========================================================================

BENCH(Keccak512_32B) {
    auto data = make_data(32);
    for (int i = 0; i < _iterations; i++) {
        uint512 h = keccak512(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

BENCH(Keccak512_1KB) {
    auto data = make_data(1024);
    for (int i = 0; i < _iterations; i++) {
        uint512 h = keccak512(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

// ===========================================================================
// Hash comparison utilities
// ===========================================================================

BENCH(HashMeetsTarget) {
    uint256 target;
    std::memset(target.data(), 0xFF, 32);
    target.data()[0] = 0x0F;  // moderately restrictive target

    auto data = make_data(32);
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        uint256 hash = keccak256(data.data(), data.size());
        bool ok = hash_meets_target(hash, target);
        (void)ok;
    }
}

BENCH(CountLeadingZeros) {
    auto data = make_data(32);
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        uint256 hash = keccak256(data.data(), data.size());
        int zeros = count_leading_zeros(hash);
        (void)zeros;
    }
}

// ===========================================================================
// Merkle branch / proof
// ===========================================================================

BENCH(MerkleBranch_100Tx) {
    std::vector<uint256> leaves(100);
    for (size_t j = 0; j < leaves.size(); j++) {
        std::memset(leaves[j].data(), static_cast<int>(j % 256), 32);
    }
    for (int i = 0; i < _iterations; i++) {
        auto branch = compute_merkle_branch(leaves, static_cast<size_t>(i % 100));
        if (branch.empty() && leaves.size() > 1) break;
    }
}

BENCH(MerkleVerify_100Tx) {
    std::vector<uint256> leaves(100);
    for (size_t j = 0; j < leaves.size(); j++) {
        std::memset(leaves[j].data(), static_cast<int>(j % 256), 32);
    }
    uint256 root = compute_merkle_root(leaves);
    auto branch = compute_merkle_branch(leaves, 42);

    for (int i = 0; i < _iterations; i++) {
        bool ok = verify_merkle_branch(leaves[42], branch, 42, root);
        if (!ok) break;
    }
}

// ===========================================================================
// CKeccak256D (double hash incremental)
// ===========================================================================

BENCH(CKeccak256D_Incremental) {
    auto chunk = make_data(128);
    for (int i = 0; i < _iterations; i++) {
        CKeccak256D hasher;
        hasher.update(chunk.data(), chunk.size());
        hasher.update(chunk.data(), chunk.size());
        uint256 h = hasher.finalize();
        chunk[0] = h.data()[0];
    }
}

// ===========================================================================
// Throughput (MB/s) oriented benchmarks
// ===========================================================================

BENCH(Keccak256_Throughput_16KB) {
    auto data = make_data(16384);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

BENCH(Keccak256_Throughput_64KB) {
    auto data = make_data(65536);
    for (int i = 0; i < _iterations; i++) {
        uint256 h = keccak256(data.data(), data.size());
        data[0] = h.data()[0];
    }
}

} // namespace flow::bench
