// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Block header: 308 bytes, fixed layout.
// Block hash = keccak256d(header[0..243]) — unsigned portion.
// Signature covers header[0..243].

#pragma once

#include "core/types.h"
#include "core/hash.h"
#include "core/serialize.h"

#include <vector>

namespace flow {

// Forward declaration
class CTransaction;

// ─── Block Header (308 bytes) ─────────────────────────────────
//
// Offset Bytes Field
// 0      32    prev_hash
// 32     32    merkle_root
// 64     8     timestamp
// 72     8     height
// 80     4     val_loss (float32)
// 84     4     prev_val_loss (float32)
// 88     4     nbits (compact difficulty)
// 92     4     train_steps
// 96     32    dataset_hash
// 128    32    delta_hash
// 160    4     d_model
// 164    4     n_layers
// 168    4     d_ff
// 172    4     n_experts
// 176    4     stagnation_count
// 180    4     n_heads
// 184    4     rank
// 188    24    reserved (zeros)
// 212    32    miner_pubkey
// 244    64    miner_sig
// ────────────────────────────
// Total: 308 bytes

static constexpr size_t BLOCK_HEADER_SIZE = 308;
static constexpr size_t BLOCK_HEADER_UNSIGNED_SIZE = 244; // [0..243]
static constexpr size_t RESERVED_SIZE = 24;

struct CBlockHeader {
    Hash256   prev_hash;
    Hash256   merkle_root;
    int64_t   timestamp{0};
    uint64_t  height{0};
    float     val_loss{0.0f};
    float     prev_val_loss{0.0f};
    uint32_t  nbits{0};
    uint32_t  train_steps{0};
    Hash256   dataset_hash;
    Hash256   delta_hash;
    uint32_t  d_model{0};
    uint32_t  n_layers{0};
    uint32_t  d_ff{0};
    uint32_t  n_experts{0};
    uint32_t  stagnation_count{0};
    uint32_t  n_heads{0};
    uint32_t  rank{0};
    uint8_t   reserved[RESERVED_SIZE]{};
    PubKey    miner_pubkey;
    Signature miner_sig;

    // Serialize the full 308-byte header
    std::array<uint8_t, BLOCK_HEADER_SIZE> serialize() const;

    // Deserialize from exactly 308 bytes
    static CBlockHeader deserialize(const uint8_t* data);

    // Get the unsigned portion [0..243] for hashing and signing
    std::array<uint8_t, BLOCK_HEADER_UNSIGNED_SIZE> unsigned_bytes() const;

    // Block hash = keccak256d(header[0..243])
    Hash256 get_hash() const;

    bool operator==(const CBlockHeader& other) const {
        return serialize() == other.serialize();
    }
};

// ─── Full Block ───────────────────────────────────────────────

struct CBlock {
    CBlockHeader header;
    std::vector<CTransaction> vtx;
    std::vector<uint8_t> delta_payload;

    // Serialize entire block: header + compact_size(tx_count) + txs + delta
    std::vector<uint8_t> serialize() const;

    // Deserialize a full block from bytes
    static CBlock deserialize(const std::vector<uint8_t>& data);

    // Compute merkle root from transactions
    Hash256 compute_merkle_root() const;

    Hash256 get_hash() const { return header.get_hash(); }
};

} // namespace flow
