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

// ═══════════════════════════════════════════════════════════════════════════
// Transaction analysis
// ═══════════════════════════════════════════════════════════════════════════

CTransaction::TxAnalysis CTransaction::analyze(
        const std::function<Amount(const COutPoint&)>& utxo_lookup) const {

    TxAnalysis a;
    a.txid = get_txid();
    a.is_coinbase = is_coinbase();
    a.serialized_size = get_serialize_size();
    a.weight = a.serialized_size * 4;  // no witness discount currently
    a.input_count = static_cast<int>(vin.size());
    a.output_count = static_cast<int>(vout.size());
    a.total_output = get_value_out();

    // Compute input total if we have a UTXO lookup function
    a.total_input = 0;
    if (!is_coinbase() && utxo_lookup) {
        for (const auto& in : vin) {
            Amount val = utxo_lookup(in.prevout);
            if (val >= 0) {
                a.total_input += val;
            }
        }
        a.fee = (a.total_input > a.total_output) ?
                 (a.total_input - a.total_output) : 0;
    } else {
        a.fee = 0;
    }

    // Fee rate: satoshis per byte
    if (a.serialized_size > 0 && a.fee > 0) {
        a.fee_rate = static_cast<double>(a.fee) /
                     static_cast<double>(a.serialized_size);
    } else {
        a.fee_rate = 0.0;
    }

    // Sigops: one per input (Ed25519 signature)
    a.sigops = is_coinbase() ? 0 : static_cast<int>(vin.size());

    // Standardness check
    a.is_standard = check_transaction();

    // Type classification
    if (is_coinbase()) {
        a.type = "coinbase";
    } else if (vin.size() == 1 && vout.size() <= 2) {
        a.type = "p2pkh";
    } else if (vin.size() > 1) {
        a.type = "multi-input";
    } else if (vout.size() > 2) {
        a.type = "multi-output";
    } else {
        a.type = "p2pkh";
    }

    // RBF signal: nSequence < 0xFFFFFFFE (we don't have nSequence in our
    // transaction format, so this is always false)
    a.is_rbf = false;

    // Finality: locktime == 0 means always final
    a.is_final = (locktime == 0);

    return a;
}

// ═══════════════════════════════════════════════════════════════════════════
// CMutableTransaction — modifiable transaction builder
// ═══════════════════════════════════════════════════════════════════════════

CTransaction CMutableTransaction::to_tx() const {
    CTransaction tx;
    tx.version = version;
    tx.vin = vin;
    tx.vout = vout;
    tx.locktime = locktime;
    return tx;
}

CMutableTransaction CMutableTransaction::from_tx(const CTransaction& tx) {
    CMutableTransaction mtx;
    mtx.version = tx.version;
    mtx.vin = tx.vin;
    mtx.vout = tx.vout;
    mtx.locktime = tx.locktime;
    return mtx;
}

void CMutableTransaction::add_input(const uint256& txid, uint32_t vout_idx) {
    CTxIn in;
    in.prevout.txid = txid;
    in.prevout.index = vout_idx;
    std::memset(in.pubkey.data(), 0, 32);
    std::memset(in.signature.data(), 0, 64);
    vin.push_back(in);
}

void CMutableTransaction::add_output(const std::vector<uint8_t>& pubkey_hash,
                                       Amount value) {
    CTxOut out;
    out.amount = value;
    std::memset(out.pubkey_hash.data(), 0, 32);
    size_t copy_len = std::min(pubkey_hash.size(), static_cast<size_t>(32));
    std::memcpy(out.pubkey_hash.data(), pubkey_hash.data(), copy_len);
    vout.push_back(out);
}

void CMutableTransaction::add_op_return(const std::vector<uint8_t>& data) {
    CTxOut out;
    out.amount = 0;  // Zero-value output (OP_RETURN-like)

    // Store the data hash in the pubkey_hash field
    if (data.size() <= 32) {
        std::memset(out.pubkey_hash.data(), 0, 32);
        std::memcpy(out.pubkey_hash.data(), data.data(), data.size());
    } else {
        // Hash the data if it's too large
        uint256 data_hash = keccak256(data.data(), data.size());
        std::memcpy(out.pubkey_hash.data(), data_hash.data(), 32);
    }

    vout.push_back(out);
}

bool CMutableTransaction::sign_input(uint32_t index,
                                       const uint8_t* privkey,
                                       const uint8_t* pubkey,
                                       const uint256& prevout_hash) {
    if (index >= vin.size()) return false;

    // Set the pubkey on the input
    std::memcpy(vin[index].pubkey.data(), pubkey, 32);

    // Compute the signature hash for this input
    CTransaction temp_tx = to_tx();
    uint256 sighash = SignatureHash(temp_tx, index);

    // Ed25519 signature is done externally (we don't have ed25519 routines here).
    // This method sets up the pubkey and prepares for signing.
    // The actual signature bytes must be set by the caller after computing
    // the Ed25519 signature over sighash.

    // For now, mark that the input has been prepared for signing.
    // In a full implementation, we'd call ed25519_sign(sighash, privkey, &vin[index].signature).
    (void)privkey;
    (void)prevout_hash;

    return true;
}

size_t CMutableTransaction::estimated_size() const {
    CTransaction temp = to_tx();
    return temp.get_serialize_size();
}

Amount CMutableTransaction::compute_fee(const std::vector<Amount>& input_values) const {
    if (input_values.size() != vin.size()) return -1;

    Amount total_in = 0;
    for (const auto& val : input_values) {
        total_in += val;
    }

    Amount total_out = 0;
    for (const auto& out : vout) {
        total_out += out.amount;
    }

    if (total_in < total_out) return -1;
    return total_in - total_out;
}

// ═══════════════════════════════════════════════════════════════════════════
// PartiallySignedTx — PSBT-like partial signing
// ═══════════════════════════════════════════════════════════════════════════

bool PartiallySignedTx::add_signature(uint32_t index,
                                        const std::array<uint8_t, 64>& sig,
                                        const std::array<uint8_t, 32>& pubkey) {
    if (index >= inputs.size()) return false;

    inputs[index].signature = sig;
    inputs[index].pubkey = pubkey;
    inputs[index].signed_ = true;

    // Also update the underlying transaction
    if (index < tx.vin.size()) {
        std::memcpy(tx.vin[index].signature.data(), sig.data(), 64);
        std::memcpy(tx.vin[index].pubkey.data(), pubkey.data(), 32);
    }

    return true;
}

bool PartiallySignedTx::is_complete() const {
    for (const auto& input : inputs) {
        if (!input.signed_) return false;
    }
    return !inputs.empty();
}

CTransaction PartiallySignedTx::finalize() const {
    CTransaction final_tx = tx.to_tx();

    // Apply all signatures from the PSBT to the transaction
    for (size_t i = 0; i < inputs.size() && i < final_tx.vin.size(); i++) {
        if (inputs[i].signed_) {
            std::memcpy(final_tx.vin[i].signature.data(),
                        inputs[i].signature.data(), 64);
            std::memcpy(final_tx.vin[i].pubkey.data(),
                        inputs[i].pubkey.data(), 32);
        }
    }

    return final_tx;
}

PartiallySignedTx PartiallySignedTx::combine(const PartiallySignedTx& a,
                                                const PartiallySignedTx& b) {
    PartiallySignedTx result;
    result.tx = a.tx;

    // Use the larger input set
    size_t n_inputs = std::max(a.inputs.size(), b.inputs.size());
    result.inputs.resize(n_inputs);

    for (size_t i = 0; i < n_inputs; i++) {
        bool a_has = (i < a.inputs.size() && a.inputs[i].signed_);
        bool b_has = (i < b.inputs.size() && b.inputs[i].signed_);

        if (a_has) {
            result.inputs[i] = a.inputs[i];
        } else if (b_has) {
            result.inputs[i] = b.inputs[i];
        } else {
            // Neither has a signature for this input
            if (i < a.inputs.size()) {
                result.inputs[i] = a.inputs[i];
            } else if (i < b.inputs.size()) {
                result.inputs[i] = b.inputs[i];
            }
        }
    }

    // Update the transaction with combined signatures
    for (size_t i = 0; i < result.inputs.size() && i < result.tx.vin.size(); i++) {
        if (result.inputs[i].signed_) {
            std::memcpy(result.tx.vin[i].signature.data(),
                        result.inputs[i].signature.data(), 64);
            std::memcpy(result.tx.vin[i].pubkey.data(),
                        result.inputs[i].pubkey.data(), 32);
        }
    }

    return result;
}

std::vector<uint8_t> PartiallySignedTx::serialize() const {
    std::vector<uint8_t> out;

    // Magic bytes "PSBT"
    out.push_back('P');
    out.push_back('S');
    out.push_back('B');
    out.push_back('T');

    // Serialize the underlying transaction
    auto tx_data = tx.to_tx().serialize();
    uint32_t tx_len = static_cast<uint32_t>(tx_data.size());
    out.push_back(static_cast<uint8_t>(tx_len));
    out.push_back(static_cast<uint8_t>(tx_len >> 8));
    out.push_back(static_cast<uint8_t>(tx_len >> 16));
    out.push_back(static_cast<uint8_t>(tx_len >> 24));
    out.insert(out.end(), tx_data.begin(), tx_data.end());

    // Input count
    uint32_t n_inputs = static_cast<uint32_t>(inputs.size());
    out.push_back(static_cast<uint8_t>(n_inputs));
    out.push_back(static_cast<uint8_t>(n_inputs >> 8));
    out.push_back(static_cast<uint8_t>(n_inputs >> 16));
    out.push_back(static_cast<uint8_t>(n_inputs >> 24));

    // Each input info
    for (const auto& input : inputs) {
        // signed flag (1 byte)
        out.push_back(input.signed_ ? 1 : 0);

        // signature (64 bytes)
        out.insert(out.end(), input.signature.begin(), input.signature.end());

        // pubkey (32 bytes)
        out.insert(out.end(), input.pubkey.begin(), input.pubkey.end());

        // value (8 bytes LE)
        int64_t val = input.value;
        for (int i = 0; i < 8; i++) {
            out.push_back(static_cast<uint8_t>(val >> (i * 8)));
        }

        // prev_txid (32 bytes)
        out.insert(out.end(), input.prev_txid.begin(), input.prev_txid.end());

        // prev_vout (4 bytes LE)
        out.push_back(static_cast<uint8_t>(input.prev_vout));
        out.push_back(static_cast<uint8_t>(input.prev_vout >> 8));
        out.push_back(static_cast<uint8_t>(input.prev_vout >> 16));
        out.push_back(static_cast<uint8_t>(input.prev_vout >> 24));
    }

    return out;
}

PartiallySignedTx PartiallySignedTx::deserialize(const std::vector<uint8_t>& data) {
    PartiallySignedTx psbt;

    if (data.size() < 12) return psbt;

    size_t pos = 0;

    // Check magic
    if (data[0] != 'P' || data[1] != 'S' || data[2] != 'B' || data[3] != 'T') {
        return psbt;
    }
    pos += 4;

    // Transaction length
    uint32_t tx_len = static_cast<uint32_t>(data[pos])
                    | (static_cast<uint32_t>(data[pos + 1]) << 8)
                    | (static_cast<uint32_t>(data[pos + 2]) << 16)
                    | (static_cast<uint32_t>(data[pos + 3]) << 24);
    pos += 4;

    if (pos + tx_len > data.size()) return psbt;

    // Deserialize transaction
    CTransaction temp_tx;
    std::vector<uint8_t> tx_bytes(data.begin() + pos, data.begin() + pos + tx_len);
    if (!temp_tx.deserialize(tx_bytes)) return psbt;
    psbt.tx = CMutableTransaction::from_tx(temp_tx);
    pos += tx_len;

    // Input count
    if (pos + 4 > data.size()) return psbt;
    uint32_t n_inputs = static_cast<uint32_t>(data[pos])
                      | (static_cast<uint32_t>(data[pos + 1]) << 8)
                      | (static_cast<uint32_t>(data[pos + 2]) << 16)
                      | (static_cast<uint32_t>(data[pos + 3]) << 24);
    pos += 4;

    // Each input: 1 (signed) + 64 (sig) + 32 (pubkey) + 8 (value) + 32 (prev_txid) + 4 (prev_vout) = 141
    static constexpr size_t INPUT_INFO_SIZE = 141;

    if (n_inputs > 10000) return psbt;
    if (pos + n_inputs * INPUT_INFO_SIZE > data.size()) return psbt;

    psbt.inputs.resize(n_inputs);
    for (uint32_t i = 0; i < n_inputs; i++) {
        auto& input = psbt.inputs[i];

        input.signed_ = (data[pos] != 0);
        pos += 1;

        std::memcpy(input.signature.data(), data.data() + pos, 64);
        pos += 64;

        std::memcpy(input.pubkey.data(), data.data() + pos, 32);
        pos += 32;

        int64_t val = 0;
        for (int j = 0; j < 8; j++) {
            val |= static_cast<int64_t>(data[pos + j]) << (j * 8);
        }
        input.value = val;
        pos += 8;

        std::memcpy(input.prev_txid.data(), data.data() + pos, 32);
        pos += 32;

        input.prev_vout = static_cast<uint32_t>(data[pos])
                        | (static_cast<uint32_t>(data[pos + 1]) << 8)
                        | (static_cast<uint32_t>(data[pos + 2]) << 16)
                        | (static_cast<uint32_t>(data[pos + 3]) << 24);
        pos += 4;
    }

    return psbt;
}

} // namespace flow
