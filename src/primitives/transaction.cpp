// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "transaction.h"

#include <cstring>

namespace flow {

std::vector<uint8_t> CTransaction::serialize() const {
    VectorWriter w;

    // Version
    w.write_u32(version);

    // Inputs
    w.write_compact_size(vin.size());
    for (const auto& in : vin) {
        w.write_bytes(std::span<const uint8_t>(in.prevout.txid.bytes(), 32));
        w.write_u32(in.prevout.vout);
        w.write_bytes(std::span<const uint8_t>(in.sig.bytes(), 64));
        w.write_bytes(std::span<const uint8_t>(in.pubkey.bytes(), 32));
    }

    // Outputs
    w.write_compact_size(vout.size());
    for (const auto& out : vout) {
        w.write_i64(out.amount.value);
        w.write_bytes(std::span<const uint8_t>(out.pubkey_hash.bytes(), 20));
    }

    return w.release();
}

CTransaction CTransaction::deserialize(SpanReader& reader) {
    CTransaction tx;

    tx.version = reader.read_u32();

    // Inputs
    uint64_t in_count = reader.read_compact_size();
    tx.vin.resize(in_count);
    for (auto& in : tx.vin) {
        reader.read_bytes(in.prevout.txid.bytes(), 32);
        in.prevout.vout = reader.read_u32();
        reader.read_bytes(in.sig.bytes(), 64);
        reader.read_bytes(in.pubkey.bytes(), 32);
    }

    // Outputs
    uint64_t out_count = reader.read_compact_size();
    tx.vout.resize(out_count);
    for (auto& out : tx.vout) {
        out.amount = Amount{reader.read_i64()};
        reader.read_bytes(out.pubkey_hash.bytes(), 20);
    }

    return tx;
}

Hash256 CTransaction::get_hash() const {
    if (!hash_computed_) {
        auto data = serialize();
        cached_hash_ = keccak256d(data.data(), data.size());
        hash_computed_ = true;
    }
    return cached_hash_;
}

std::vector<uint8_t> CTransaction::signing_data() const {
    // Everything except the signatures: version + prevouts + outputs
    VectorWriter w;
    w.write_u32(version);

    w.write_compact_size(vin.size());
    for (const auto& in : vin) {
        w.write_bytes(std::span<const uint8_t>(in.prevout.txid.bytes(), 32));
        w.write_u32(in.prevout.vout);
        // Skip sig (64 bytes) — this is what we're signing
        w.write_bytes(std::span<const uint8_t>(in.pubkey.bytes(), 32));
    }

    w.write_compact_size(vout.size());
    for (const auto& out : vout) {
        w.write_i64(out.amount.value);
        w.write_bytes(std::span<const uint8_t>(out.pubkey_hash.bytes(), 20));
    }

    return w.release();
}

CTransaction make_coinbase(Amount reward, const Blob<20>& miner_pubkey_hash,
                           uint64_t height) {
    CTransaction tx;
    tx.version = CTransaction::CURRENT_VERSION;

    // Coinbase input: null prevout, height encoded in sig field
    CTxIn coinbase_in;
    coinbase_in.prevout.txid.set_zero();
    coinbase_in.prevout.vout = 0xFFFFFFFF;
    // Encode height in the first 8 bytes of the signature field (coinbase data)
    write_le64(coinbase_in.sig.bytes(), height);
    tx.vin.push_back(coinbase_in);

    // Single output to miner
    CTxOut out;
    out.amount = reward;
    out.pubkey_hash = miner_pubkey_hash;
    tx.vout.push_back(out);

    return tx;
}

} // namespace flow
