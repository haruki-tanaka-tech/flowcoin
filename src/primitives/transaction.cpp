// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "transaction.h"
#include "compact.h"
#include "../hash/keccak.h"
#include "../util/strencodings.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>

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
    CompactSize::encode_to(v, buf);
}

static void write_bytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

static uint32_t read_u32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

static int64_t read_i64(const uint8_t* p) {
    uint64_t u = 0;
    for (int i = 0; i < 8; ++i)
        u |= static_cast<uint64_t>(p[i]) << (i * 8);
    int64_t result;
    std::memcpy(&result, &u, 8);
    return result;
}

// ===========================================================================
// COutPoint
// ===========================================================================

std::vector<uint8_t> COutPoint::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(36);
    write_bytes(buf, txid.data(), 32);
    write_u32(buf, index);
    return buf;
}

bool COutPoint::deserialize(const uint8_t* data, size_t len) {
    if (len < 36) return false;
    std::memcpy(txid.data(), data, 32);
    index = read_u32(data + 32);
    return true;
}

std::string COutPoint::to_string() const {
    return hex_encode_reverse<32>(txid.data()) + ":" + std::to_string(index);
}

// ===========================================================================
// CTxIn
// ===========================================================================

std::vector<uint8_t> CTxIn::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(132);
    write_bytes(buf, prevout.txid.data(), 32);
    write_u32(buf, prevout.index);
    write_bytes(buf, pubkey.data(), 32);
    write_bytes(buf, signature.data(), 64);
    return buf;
}

std::vector<uint8_t> CTxIn::serialize_for_hash() const {
    std::vector<uint8_t> buf;
    buf.reserve(68);
    write_bytes(buf, prevout.txid.data(), 32);
    write_u32(buf, prevout.index);
    write_bytes(buf, pubkey.data(), 32);
    // Signature is NOT included
    return buf;
}

// ===========================================================================
// CTxOut
// ===========================================================================

std::vector<uint8_t> CTxOut::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(40);
    write_i64(buf, amount);
    write_bytes(buf, pubkey_hash.data(), 32);
    return buf;
}

std::string CTxOut::to_string() const {
    std::ostringstream ss;
    ss << "CTxOut(amount=" << amount
       << " pkh=" << hex_encode(pubkey_hash.data(), 8) << "...)";
    return ss.str();
}

// ---------------------------------------------------------------------------
// serialize_for_hash -- used for txid computation (excludes input signatures)
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
        // Pubkey (32 bytes) -- included in txid for binding
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
// serialize -- full serialization including signatures
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
// deserialize -- from raw bytes with consumed count
// ---------------------------------------------------------------------------

bool CTransaction::deserialize(const uint8_t* data, size_t len, size_t& consumed) {
    if (len < 4) return false;

    size_t pos = 0;

    // Version
    version = read_u32(data + pos);
    pos += 4;

    // Input count
    uint64_t vin_count = 0;
    size_t cs = CompactSize::decode(data + pos, len - pos, vin_count);
    if (cs == 0) return false;
    pos += cs;

    if (vin_count > MAX_TX_INPUTS) return false;

    vin.resize(static_cast<size_t>(vin_count));
    for (uint64_t j = 0; j < vin_count; ++j) {
        // txid (32) + index (4) + pubkey (32) + sig (64) = 132
        if (pos + 132 > len) return false;
        std::memcpy(vin[j].prevout.txid.data(), data + pos, 32);
        pos += 32;
        vin[j].prevout.index = read_u32(data + pos);
        pos += 4;
        std::memcpy(vin[j].pubkey.data(), data + pos, 32);
        pos += 32;
        std::memcpy(vin[j].signature.data(), data + pos, 64);
        pos += 64;
    }

    // Output count
    uint64_t vout_count = 0;
    cs = CompactSize::decode(data + pos, len - pos, vout_count);
    if (cs == 0) return false;
    pos += cs;

    if (vout_count > MAX_TX_OUTPUTS) return false;

    vout.resize(static_cast<size_t>(vout_count));
    for (uint64_t j = 0; j < vout_count; ++j) {
        // amount (8) + pubkey_hash (32) = 40
        if (pos + 40 > len) return false;
        vout[j].amount = read_i64(data + pos);
        pos += 8;
        std::memcpy(vout[j].pubkey_hash.data(), data + pos, 32);
        pos += 32;
    }

    // Locktime
    if (pos + 8 > len) return false;
    locktime = read_i64(data + pos);
    pos += 8;

    consumed = pos;
    return true;
}

bool CTransaction::deserialize(const std::vector<uint8_t>& data) {
    size_t consumed = 0;
    return deserialize(data.data(), data.size(), consumed);
}

// ---------------------------------------------------------------------------
// get_txid -- double keccak256 of the signable portion
// ---------------------------------------------------------------------------

uint256 CTransaction::get_txid() const {
    auto data = serialize_for_hash();
    return keccak256d(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// get_value_in -- total input value via UTXO lookup
// ---------------------------------------------------------------------------

Amount CTransaction::get_value_in(std::function<Amount(const COutPoint&)> utxo_lookup) const {
    if (is_coinbase()) return 0;

    Amount total = 0;
    for (const auto& in : vin) {
        Amount val = utxo_lookup(in.prevout);
        if (val < 0) return -1;  // UTXO not found
        total += val;
    }
    return total;
}

// ---------------------------------------------------------------------------
// is_final
// ---------------------------------------------------------------------------

bool CTransaction::is_final(uint64_t block_height, int64_t block_time) const {
    if (locktime == 0) return true;

    // locktime < 500,000,000 is interpreted as a block height
    // locktime >= 500,000,000 is interpreted as a Unix timestamp
    if (locktime < 500'000'000) {
        return static_cast<uint64_t>(locktime) < block_height;
    }
    return locktime < block_time;
}

// ---------------------------------------------------------------------------
// check_transaction -- basic validity (context-free)
// ---------------------------------------------------------------------------

bool CTransaction::check_transaction() const {
    // Must have at least one input.
    if (vin.empty()) return false;

    // Must have at least one output.
    if (vout.empty()) return false;

    // Check input count limit.
    if (vin.size() > MAX_TX_INPUTS) return false;

    // Check output count limit.
    if (vout.size() > MAX_TX_OUTPUTS) return false;

    // Check output values.
    Amount total_out = 0;
    for (const auto& out : vout) {
        if (out.amount < 0) return false;
        if (out.amount > MAX_MONEY) return false;
        total_out += out.amount;
        if (total_out < 0 || total_out > MAX_MONEY) return false;
    }

    // Check for duplicate inputs.
    // Use a set of outpoints for O(n log n) duplicate detection.
    std::set<std::pair<uint256, uint32_t>> seen;
    for (const auto& in : vin) {
        // Coinbase inputs are allowed to have null prevout; skip dup check for them.
        if (in.is_coinbase()) continue;
        auto key = std::make_pair(in.prevout.txid, in.prevout.index);
        if (!seen.insert(key).second) return false;  // duplicate
    }

    // Coinbase-specific checks.
    if (is_coinbase()) {
        // Coinbase must have exactly one input.
        if (vin.size() != 1) return false;
    } else {
        // Non-coinbase transactions must not have null inputs.
        for (const auto& in : vin) {
            if (in.prevout.is_null()) return false;
        }
    }

    // Check serialized size limit.
    size_t sz = get_serialize_size();
    if (sz > MAX_TX_SIZE) return false;

    return true;
}

// ---------------------------------------------------------------------------
// signature_hash
// ---------------------------------------------------------------------------

uint256 CTransaction::signature_hash(uint32_t input_index) const {
    return SignatureHash(*this, input_index);
}

// ---------------------------------------------------------------------------
// get_serialize_size -- pre-compute serialized size
// ---------------------------------------------------------------------------

size_t CTransaction::get_serialize_size() const {
    size_t size = 0;

    // Version (4 bytes)
    size += 4;

    // Input count (CompactSize)
    size += CompactSize::encoded_size(vin.size());

    // Inputs: each is 132 bytes (32 txid + 4 index + 32 pubkey + 64 sig)
    size += vin.size() * 132;

    // Output count (CompactSize)
    size += CompactSize::encoded_size(vout.size());

    // Outputs: each is 40 bytes (8 amount + 32 pubkey_hash)
    size += vout.size() * 40;

    // Locktime (8 bytes)
    size += 8;

    return size;
}

// ---------------------------------------------------------------------------
// to_string
// ---------------------------------------------------------------------------

std::string CTransaction::to_string() const {
    std::ostringstream ss;
    uint256 txid = get_txid();
    ss << "CTransaction(txid=" << hex_encode_reverse<32>(txid.data())
       << " ver=" << version
       << " vin=" << vin.size()
       << " vout=" << vout.size()
       << " locktime=" << locktime;
    if (is_coinbase()) ss << " coinbase";
    ss << " value_out=" << get_value_out()
       << ")";
    return ss.str();
}

// ===========================================================================
// SignatureHash -- free function
// ===========================================================================

uint256 SignatureHash(const CTransaction& tx, uint32_t input_index) {
    // The signature hash is:
    //   keccak256d(serialize_for_hash(tx) || input_index_as_LE32)
    //
    // This binds the signature to both the transaction contents and the
    // specific input being signed, preventing signature reuse across inputs.

    auto data = tx.serialize_for_hash();

    // Append input_index as 4-byte little-endian
    data.push_back(static_cast<uint8_t>(input_index));
    data.push_back(static_cast<uint8_t>(input_index >> 8));
    data.push_back(static_cast<uint8_t>(input_index >> 16));
    data.push_back(static_cast<uint8_t>(input_index >> 24));

    return keccak256d(data.data(), data.size());
}

} // namespace flow
