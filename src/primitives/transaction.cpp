// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "transaction.h"
#include "../hash/keccak.h"

#include <cstring>

namespace flow {

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

static void write_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v));
    buf.push_back(static_cast<uint8_t>(v >> 8));
    buf.push_back(static_cast<uint8_t>(v >> 16));
    buf.push_back(static_cast<uint8_t>(v >> 24));
}

static void write_i64(std::vector<uint8_t>& buf, int64_t v) {
    uint64_t u;
    std::memcpy(&u, &v, 8);
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>(u >> (i * 8)));
    }
}

static void write_varint(std::vector<uint8_t>& buf, uint64_t v) {
    if (v < 0xFD) {
        buf.push_back(static_cast<uint8_t>(v));
    } else if (v <= 0xFFFF) {
        buf.push_back(0xFD);
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
    } else if (v <= 0xFFFFFFFF) {
        buf.push_back(0xFE);
        write_u32(buf, static_cast<uint32_t>(v));
    } else {
        buf.push_back(0xFF);
        write_i64(buf, static_cast<int64_t>(v));
    }
}

static void write_bytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

// ---------------------------------------------------------------------------
// serialize_for_hash — used for txid computation (excludes input signatures)
// ---------------------------------------------------------------------------

std::vector<uint8_t> CTransaction::serialize_for_hash() const {
    std::vector<uint8_t> buf;
    buf.reserve(256);

    // Version
    write_u32(buf, version);

    // Input count
    write_varint(buf, vin.size());

    for (const auto& in : vin) {
        // Prevout: txid (32 bytes) + index (4 bytes)
        write_bytes(buf, in.prevout.txid.data(), 32);
        write_u32(buf, in.prevout.index);
        // Pubkey (32 bytes) — included in txid for binding
        write_bytes(buf, in.pubkey.data(), 32);
        // Signature is NOT included (this is what we sign over)
    }

    // Output count
    write_varint(buf, vout.size());

    for (const auto& out : vout) {
        write_i64(buf, out.amount);
        write_bytes(buf, out.pubkey_hash.data(), 32);
    }

    // Locktime
    write_i64(buf, locktime);

    return buf;
}

// ---------------------------------------------------------------------------
// serialize — full serialization including signatures
// ---------------------------------------------------------------------------

std::vector<uint8_t> CTransaction::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(512);

    write_u32(buf, version);

    write_varint(buf, vin.size());
    for (const auto& in : vin) {
        write_bytes(buf, in.prevout.txid.data(), 32);
        write_u32(buf, in.prevout.index);
        write_bytes(buf, in.pubkey.data(), 32);
        write_bytes(buf, in.signature.data(), 64);
    }

    write_varint(buf, vout.size());
    for (const auto& out : vout) {
        write_i64(buf, out.amount);
        write_bytes(buf, out.pubkey_hash.data(), 32);
    }

    write_i64(buf, locktime);

    return buf;
}

// ---------------------------------------------------------------------------
// get_txid — double keccak256 of the signable portion
// ---------------------------------------------------------------------------

uint256 CTransaction::get_txid() const {
    auto data = serialize_for_hash();
    return keccak256d(data.data(), data.size());
}

} // namespace flow
