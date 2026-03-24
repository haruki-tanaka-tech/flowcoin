// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "block.h"
#include "../hash/keccak.h"

#include <cstring>

namespace flow {

// ---------------------------------------------------------------------------
// Serialization helpers (little-endian)
// ---------------------------------------------------------------------------

static void append_bytes(std::vector<uint8_t>& buf, const uint8_t* src, size_t n) {
    buf.insert(buf.end(), src, src + n);
}

static void append_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v));
    buf.push_back(static_cast<uint8_t>(v >> 8));
    buf.push_back(static_cast<uint8_t>(v >> 16));
    buf.push_back(static_cast<uint8_t>(v >> 24));
}

static void append_u64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
}

static void append_i64(std::vector<uint8_t>& buf, int64_t v) {
    uint64_t u;
    std::memcpy(&u, &v, 8);
    append_u64(buf, u);
}

static void append_float(std::vector<uint8_t>& buf, float f) {
    uint32_t bits;
    std::memcpy(&bits, &f, 4);
    append_u32(buf, bits);
}

// ---------------------------------------------------------------------------
// get_unsigned_data — 244 bytes (bytes 0-243 of the header)
// ---------------------------------------------------------------------------

std::vector<uint8_t> CBlockHeader::get_unsigned_data() const {
    std::vector<uint8_t> buf;
    buf.reserve(244);

    // 32-byte fields (4 * 32 = 128 bytes)
    append_bytes(buf, prev_hash.data(), 32);        // 0-31
    append_bytes(buf, merkle_root.data(), 32);       // 32-63
    append_bytes(buf, training_hash.data(), 32);     // 64-95
    append_bytes(buf, dataset_hash.data(), 32);      // 96-127

    // 8-byte fields (2 * 8 = 16 bytes)
    append_u64(buf, height);                         // 128-135
    append_i64(buf, timestamp);                      // 136-143

    // 4-byte fields
    append_u32(buf, nbits);                          // 144-147
    append_float(buf, val_loss);                     // 148-151
    append_float(buf, prev_val_loss);                // 152-155

    // Architecture dimensions (6 * 4 = 24 bytes)
    append_u32(buf, d_model);                        // 156-159
    append_u32(buf, n_layers);                       // 160-163
    append_u32(buf, d_ff);                           // 164-167
    append_u32(buf, n_heads);                        // 168-171
    append_u32(buf, gru_dim);                        // 172-175
    append_u32(buf, n_slots);                        // 176-179

    // Training metadata (2 * 4 = 8 bytes)
    append_u32(buf, train_steps);                    // 180-183
    append_u32(buf, stagnation);                     // 184-187

    // Delta reference (4 * 4 = 16 bytes)
    append_u32(buf, delta_offset);                   // 188-191
    append_u32(buf, delta_length);                   // 192-195
    append_u32(buf, sparse_count);                   // 196-199
    append_float(buf, sparse_threshold);             // 200-203

    // Nonce + version (2 * 4 = 8 bytes)
    append_u32(buf, nonce);                          // 204-207
    append_u32(buf, version);                        // 208-211

    // Miner pubkey (32 bytes)
    append_bytes(buf, miner_pubkey.data(), 32);      // 212-243

    // Total: 128 + 16 + 8 + 24 + 8 + 16 + 8 + 4 + 32 = 244 bytes
    // Signature (bytes 244-307) is NOT included — that's what we sign over.

    return buf;
}

// ---------------------------------------------------------------------------
// get_hash — keccak256d of the unsigned header
// ---------------------------------------------------------------------------

uint256 CBlockHeader::get_hash() const {
    auto data = get_unsigned_data();
    return keccak256d(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// get_training_hash — for PoW target comparison
// ---------------------------------------------------------------------------

uint256 CBlockHeader::get_training_hash() const {
    return get_hash();
}

} // namespace flow
