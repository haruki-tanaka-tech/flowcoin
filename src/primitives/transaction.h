// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Transaction format:
//   version (4) + input_count + inputs + output_count + outputs
//
// CTxIn:  prev_txid (32) + prev_vout (4) + sig (64) + pubkey (32)
// CTxOut: amount (8) + pubkey_hash (20)
//
// Coinbase: prev_txid = 0, prev_vout = 0xFFFFFFFF, sig = coinbase data

#pragma once

#include "core/types.h"
#include "core/hash.h"
#include "core/serialize.h"

#include <vector>

namespace flow {

// ─── Transaction Input ────────────────────────────────────────

struct COutPoint {
    Hash256  txid;
    uint32_t vout{0};

    bool is_null() const { return txid.is_zero() && vout == 0xFFFFFFFF; }

    bool operator==(const COutPoint& o) const {
        return txid == o.txid && vout == o.vout;
    }
};

struct CTxIn {
    COutPoint prevout;
    Signature sig;
    PubKey    pubkey;

    bool is_coinbase() const { return prevout.is_null(); }
};

// ─── Transaction Output ───────────────────────────────────────

struct CTxOut {
    Amount  amount;
    Blob<20> pubkey_hash; // keccak256d(pubkey)[0..19]

    bool operator==(const CTxOut& o) const {
        return amount == o.amount && pubkey_hash == o.pubkey_hash;
    }
};

// ─── Transaction ──────────────────────────────────────────────

class CTransaction {
public:
    static constexpr uint32_t CURRENT_VERSION = 1;

    uint32_t version{CURRENT_VERSION};
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;

    // Serialize the full transaction
    std::vector<uint8_t> serialize() const;

    // Deserialize from bytes
    static CTransaction deserialize(SpanReader& reader);

    // Get transaction hash (cached after first computation)
    Hash256 get_hash() const;

    // Get the bytes that are signed (everything except signatures)
    // Used for producing/verifying input signatures.
    std::vector<uint8_t> signing_data() const;

    bool is_coinbase() const {
        return vin.size() == 1 && vin[0].is_coinbase();
    }

private:
    mutable Hash256 cached_hash_;
    mutable bool hash_computed_{false};
};

// Create a coinbase transaction
CTransaction make_coinbase(Amount reward, const Blob<20>& miner_pubkey_hash,
                           uint64_t height);

} // namespace flow
