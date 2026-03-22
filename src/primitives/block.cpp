// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "block.h"
#include "transaction.h"

#include <cstring>

namespace flow {

std::array<uint8_t, BLOCK_HEADER_SIZE> CBlockHeader::serialize() const {
    std::array<uint8_t, BLOCK_HEADER_SIZE> buf{};
    uint8_t* p = buf.data();

    // 0: prev_hash (32)
    std::memcpy(p, prev_hash.bytes(), 32); p += 32;
    // 32: merkle_root (32)
    std::memcpy(p, merkle_root.bytes(), 32); p += 32;
    // 64: timestamp (8)
    write_le64(p, static_cast<uint64_t>(timestamp)); p += 8;
    // 72: height (8)
    write_le64(p, height); p += 8;
    // 80: val_loss (4)
    write_le_float(p, val_loss); p += 4;
    // 84: prev_val_loss (4)
    write_le_float(p, prev_val_loss); p += 4;
    // 88: nbits (4)
    write_le32(p, nbits); p += 4;
    // 92: train_steps (4)
    write_le32(p, train_steps); p += 4;
    // 96: dataset_hash (32)
    std::memcpy(p, dataset_hash.bytes(), 32); p += 32;
    // 128: delta_hash (32)
    std::memcpy(p, delta_hash.bytes(), 32); p += 32;
    // 160: d_model (4)
    write_le32(p, d_model); p += 4;
    // 164: n_layers (4)
    write_le32(p, n_layers); p += 4;
    // 168: d_ff (4)
    write_le32(p, d_ff); p += 4;
    // 172: n_experts (4)
    write_le32(p, n_experts); p += 4;
    // 176: stagnation_count (4)
    write_le32(p, stagnation_count); p += 4;
    // 180: n_heads (4)
    write_le32(p, n_heads); p += 4;
    // 184: rank (4)
    write_le32(p, rank); p += 4;
    // 188: reserved (24)
    std::memcpy(p, reserved, RESERVED_SIZE); p += RESERVED_SIZE;
    // 212: miner_pubkey (32)
    std::memcpy(p, miner_pubkey.bytes(), 32); p += 32;
    // 244: miner_sig (64)
    std::memcpy(p, miner_sig.bytes(), 64); p += 64;

    return buf;
}

CBlockHeader CBlockHeader::deserialize(const uint8_t* data) {
    CBlockHeader h;
    const uint8_t* p = data;

    std::memcpy(h.prev_hash.bytes(), p, 32); p += 32;
    std::memcpy(h.merkle_root.bytes(), p, 32); p += 32;
    h.timestamp = static_cast<int64_t>(read_le64(p)); p += 8;
    h.height = read_le64(p); p += 8;
    h.val_loss = read_le_float(p); p += 4;
    h.prev_val_loss = read_le_float(p); p += 4;
    h.nbits = read_le32(p); p += 4;
    h.train_steps = read_le32(p); p += 4;
    std::memcpy(h.dataset_hash.bytes(), p, 32); p += 32;
    std::memcpy(h.delta_hash.bytes(), p, 32); p += 32;
    h.d_model = read_le32(p); p += 4;
    h.n_layers = read_le32(p); p += 4;
    h.d_ff = read_le32(p); p += 4;
    h.n_experts = read_le32(p); p += 4;
    h.stagnation_count = read_le32(p); p += 4;
    h.n_heads = read_le32(p); p += 4;
    h.rank = read_le32(p); p += 4;
    std::memcpy(h.reserved, p, RESERVED_SIZE); p += RESERVED_SIZE;
    std::memcpy(h.miner_pubkey.bytes(), p, 32); p += 32;
    std::memcpy(h.miner_sig.bytes(), p, 64); p += 64;

    return h;
}

std::array<uint8_t, BLOCK_HEADER_UNSIGNED_SIZE> CBlockHeader::unsigned_bytes() const {
    auto full = serialize();
    std::array<uint8_t, BLOCK_HEADER_UNSIGNED_SIZE> result;
    std::memcpy(result.data(), full.data(), BLOCK_HEADER_UNSIGNED_SIZE);
    return result;
}

Hash256 CBlockHeader::get_hash() const {
    auto ub = unsigned_bytes();
    return keccak256d(ub.data(), ub.size());
}

// ─── CBlock ──────────────────────────────────────────────────

std::vector<uint8_t> CBlock::serialize() const {
    VectorWriter w;

    // Header (308 bytes, fixed)
    auto hdr = header.serialize();
    w.write(hdr.data(), hdr.size());

    // Transaction count
    w.write_compact_size(vtx.size());

    // Transactions
    for (const auto& tx : vtx) {
        auto tx_bytes = tx.serialize();
        w.write_bytes(tx_bytes);
    }

    // Delta payload (length-prefixed)
    w.write_compact_size(delta_payload.size());
    if (!delta_payload.empty()) {
        w.write_bytes(delta_payload);
    }

    return w.release();
}

CBlock CBlock::deserialize(const std::vector<uint8_t>& data) {
    CBlock block;

    if (data.size() < BLOCK_HEADER_SIZE) {
        throw std::runtime_error("block too small");
    }

    // Header (fixed 308 bytes)
    block.header = CBlockHeader::deserialize(data.data());

    SpanReader reader(std::span<const uint8_t>(data.data() + BLOCK_HEADER_SIZE,
                                                data.size() - BLOCK_HEADER_SIZE));

    // Transactions
    uint64_t tx_count = reader.read_compact_size();
    block.vtx.reserve(tx_count);
    for (uint64_t i = 0; i < tx_count; ++i) {
        block.vtx.push_back(CTransaction::deserialize(reader));
    }

    // Delta payload
    uint64_t delta_size = reader.read_compact_size();
    if (delta_size > 0) {
        block.delta_payload.resize(delta_size);
        reader.read_bytes(block.delta_payload.data(), delta_size);
    }

    return block;
}

Hash256 CBlock::compute_merkle_root() const {
    if (vtx.empty()) {
        return Hash256::ZERO;
    }

    // Compute leaf hashes
    std::vector<Hash256> hashes;
    hashes.reserve(vtx.size());
    for (const auto& tx : vtx) {
        hashes.push_back(tx.get_hash());
    }

    // Build merkle tree
    while (hashes.size() > 1) {
        std::vector<Hash256> next;
        next.reserve((hashes.size() + 1) / 2);
        for (size_t i = 0; i < hashes.size(); i += 2) {
            if (i + 1 < hashes.size()) {
                // Hash pair
                Keccak256Hasher hasher;
                hasher.update(hashes[i].bytes(), 32);
                hasher.update(hashes[i + 1].bytes(), 32);
                next.push_back(hasher.finalize());
            } else {
                // Odd element: hash with itself
                Keccak256Hasher hasher;
                hasher.update(hashes[i].bytes(), 32);
                hasher.update(hashes[i].bytes(), 32);
                next.push_back(hasher.finalize());
            }
        }
        hashes = std::move(next);
    }

    return hashes[0];
}

} // namespace flow
