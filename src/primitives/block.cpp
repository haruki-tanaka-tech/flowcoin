// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "block.h"
#include "compact.h"
#include "../hash/keccak.h"
#include "../hash/merkle.h"
#include "../util/strencodings.h"
#include "../consensus/params.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>

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

static uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

static uint64_t read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

static int64_t read_i64_le(const uint8_t* p) {
    uint64_t u = read_u64_le(p);
    int64_t result;
    std::memcpy(&result, &u, 8);
    return result;
}

static float read_float_le(const uint8_t* p) {
    uint32_t bits = read_u32_le(p);
    float f;
    std::memcpy(&f, &bits, 4);
    return f;
}

// ---------------------------------------------------------------------------
// get_unsigned_data -- 244 bytes (bytes 0-243 of the header)
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
    append_u32(buf, reserved_field);                 // 180-183 (reserved)
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
    // Signature (bytes 244-307) is NOT included -- that's what we sign over.

    return buf;
}

// ---------------------------------------------------------------------------
// get_hash -- keccak256d of the unsigned header
// ---------------------------------------------------------------------------

uint256 CBlockHeader::get_hash() const {
    auto data = get_unsigned_data();
    return keccak256d(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// get_training_hash -- keccak256(training_hash || dataset_hash) for PoW
// ---------------------------------------------------------------------------

uint256 CBlockHeader::get_training_hash() const {
    // Combine the training proof hash and dataset hash into a single
    // hash value for target comparison.
    std::vector<uint8_t> combined;
    combined.reserve(64);
    append_bytes(combined, training_hash.data(), 32);
    append_bytes(combined, dataset_hash.data(), 32);
    return keccak256(combined.data(), combined.size());
}

// ---------------------------------------------------------------------------
// serialize -- full 308-byte header
// ---------------------------------------------------------------------------

std::vector<uint8_t> CBlockHeader::serialize() const {
    std::vector<uint8_t> buf = get_unsigned_data();
    buf.reserve(BLOCK_HEADER_SIZE);
    append_bytes(buf, miner_sig.data(), 64);    // 244-307
    return buf;
}

// ---------------------------------------------------------------------------
// deserialize -- 308-byte header from raw bytes
// ---------------------------------------------------------------------------

bool CBlockHeader::deserialize(const uint8_t* data, size_t len) {
    if (len < BLOCK_HEADER_SIZE) return false;

    // Read 32-byte hash fields
    std::memcpy(prev_hash.data(), data + 0, 32);
    std::memcpy(merkle_root.data(), data + 32, 32);
    std::memcpy(training_hash.data(), data + 64, 32);
    std::memcpy(dataset_hash.data(), data + 96, 32);

    // Read integer fields
    height           = read_u64_le(data + 128);
    timestamp        = read_i64_le(data + 136);
    nbits            = read_u32_le(data + 144);
    val_loss         = read_float_le(data + 148);
    prev_val_loss    = read_float_le(data + 152);
    d_model          = read_u32_le(data + 156);
    n_layers         = read_u32_le(data + 160);
    d_ff             = read_u32_le(data + 164);
    n_heads          = read_u32_le(data + 168);
    gru_dim          = read_u32_le(data + 172);
    n_slots          = read_u32_le(data + 176);
    reserved_field   = read_u32_le(data + 180);
    stagnation       = read_u32_le(data + 184);
    delta_offset     = read_u32_le(data + 188);
    delta_length     = read_u32_le(data + 192);
    sparse_count     = read_u32_le(data + 196);
    sparse_threshold = read_float_le(data + 200);
    nonce            = read_u32_le(data + 204);
    version          = read_u32_le(data + 208);

    // Read miner identity
    std::memcpy(miner_pubkey.data(), data + 212, 32);
    std::memcpy(miner_sig.data(), data + 244, 64);

    return true;
}

// ---------------------------------------------------------------------------
// is_proof_of_training_valid
// ---------------------------------------------------------------------------

bool CBlockHeader::is_proof_of_training_valid(const uint256& target) const {
    uint256 hash = get_hash();
    // The hash must be lexicographically less than or equal to the target.
    // uint256 comparison is byte-by-byte from index 0 (least significant byte
    // in our LE layout). For PoW comparison, we need to compare as big integers:
    // hash <= target means the hash (as a 256-bit number) is at most the target.
    return hash <= target;
}

// ---------------------------------------------------------------------------
// get_hash_hex
// ---------------------------------------------------------------------------

std::string CBlockHeader::get_hash_hex() const {
    uint256 hash = get_hash();
    return hex_encode_reverse<32>(hash.data());
}

// ===========================================================================
// CBlock
// ===========================================================================

// ---------------------------------------------------------------------------
// serialize -- full block
// ---------------------------------------------------------------------------

std::vector<uint8_t> CBlock::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(BLOCK_HEADER_SIZE + 9 + vtx.size() * 256 + delta_payload.size() + 9);

    // Header (308 bytes)
    auto hdr = CBlockHeader::serialize();
    buf.insert(buf.end(), hdr.begin(), hdr.end());

    // Transaction count (CompactSize)
    CompactSize::encode_to(vtx.size(), buf);

    // Transactions
    for (const auto& tx : vtx) {
        auto tx_data = tx.serialize();
        buf.insert(buf.end(), tx_data.begin(), tx_data.end());
    }

    // Delta payload length (CompactSize) + data
    CompactSize::encode_to(delta_payload.size(), buf);
    if (!delta_payload.empty()) {
        buf.insert(buf.end(), delta_payload.begin(), delta_payload.end());
    }

    return buf;
}

// ---------------------------------------------------------------------------
// deserialize -- full block from raw bytes
// ---------------------------------------------------------------------------

bool CBlock::deserialize(const uint8_t* data, size_t len) {
    if (len < BLOCK_HEADER_SIZE) return false;

    // Deserialize header
    if (!CBlockHeader::deserialize(data, len)) return false;

    // If we only have the header, that's fine
    if (len == BLOCK_HEADER_SIZE) return true;

    size_t pos = BLOCK_HEADER_SIZE;

    // Transaction count
    uint64_t tx_count = 0;
    size_t consumed = CompactSize::decode(data + pos, len - pos, tx_count);
    if (consumed == 0) return false;
    pos += consumed;

    // Sanity check: max 100,000 transactions per block
    if (tx_count > 100000) return false;

    vtx.resize(static_cast<size_t>(tx_count));
    for (uint64_t i = 0; i < tx_count; ++i) {
        // Each transaction needs to be deserialized from the byte stream.
        // We use the CTransaction::deserialize method which returns bytes consumed.
        size_t tx_consumed = 0;
        if (!vtx[i].deserialize(data + pos, len - pos, tx_consumed)) return false;
        pos += tx_consumed;
    }

    // Delta payload
    if (pos >= len) return true;  // no delta

    uint64_t delta_len = 0;
    consumed = CompactSize::decode(data + pos, len - pos, delta_len);
    if (consumed == 0) return false;
    pos += consumed;

    if (delta_len > consensus::MAX_DELTA_SIZE) return false;
    if (delta_len > 0) {
        if (pos + delta_len > len) return false;
        delta_payload.assign(data + pos, data + pos + delta_len);
        pos += static_cast<size_t>(delta_len);
    }

    return true;
}

// ---------------------------------------------------------------------------
// get_block_size
// ---------------------------------------------------------------------------

size_t CBlock::get_block_size() const {
    size_t size = BLOCK_HEADER_SIZE;

    // Transaction count
    size += CompactSize::encoded_size(vtx.size());

    // Transactions
    for (const auto& tx : vtx) {
        size += tx.get_serialize_size();
    }

    // Delta
    size += CompactSize::encoded_size(delta_payload.size());
    size += delta_payload.size();

    return size;
}

// ---------------------------------------------------------------------------
// get_block_weight
// ---------------------------------------------------------------------------

size_t CBlock::get_block_weight() const {
    return compute_block_weight(*this, vtx, delta_payload);
}

// ---------------------------------------------------------------------------
// make_coinbase
// ---------------------------------------------------------------------------

CTransaction CBlock::make_coinbase(uint64_t cb_height, Amount reward,
                                    const std::array<uint8_t, 32>& miner_pubkey_out,
                                    const std::string& coinbase_msg) {
    CTransaction coinbase;
    coinbase.version = 1;
    coinbase.locktime = 0;

    // Coinbase input: null prevout
    CTxIn cb_in;
    cb_in.prevout = COutPoint();  // null = coinbase marker

    // Encode height in the coinbase pubkey field (BIP34 style).
    // First 8 bytes of pubkey = height as LE uint64.
    std::memset(cb_in.pubkey.data(), 0, 32);
    for (int i = 0; i < 8; ++i) {
        cb_in.pubkey[i] = static_cast<uint8_t>(cb_height >> (i * 8));
    }

    // If there's a coinbase message, encode it in the signature field.
    if (!coinbase_msg.empty()) {
        size_t msg_len = std::min(coinbase_msg.size(), static_cast<size_t>(64));
        std::memset(cb_in.signature.data(), 0, 64);
        std::memcpy(cb_in.signature.data(), coinbase_msg.data(), msg_len);
    }

    coinbase.vin.push_back(cb_in);

    // Coinbase output: reward to the miner's pubkey hash.
    CTxOut cb_out;
    cb_out.amount = reward;
    // Compute pubkey_hash = keccak256(miner_pubkey)[0..32]
    uint256 pkh = keccak256(miner_pubkey_out.data(), 32);
    std::memcpy(cb_out.pubkey_hash.data(), pkh.data(), 32);
    coinbase.vout.push_back(cb_out);

    return coinbase;
}

// ---------------------------------------------------------------------------
// verify_merkle_root
// ---------------------------------------------------------------------------

bool CBlock::verify_merkle_root() const {
    if (vtx.empty()) return merkle_root.is_null();
    uint256 computed = compute_merkle_root();
    return computed == merkle_root;
}

// ---------------------------------------------------------------------------
// compute_merkle_root
// ---------------------------------------------------------------------------

uint256 CBlock::compute_merkle_root() const {
    if (vtx.empty()) {
        uint256 null_hash;
        null_hash.set_null();
        return null_hash;
    }

    std::vector<uint256> tx_hashes;
    tx_hashes.reserve(vtx.size());
    for (const auto& tx : vtx) {
        tx_hashes.push_back(tx.get_txid());
    }

    return flow::compute_merkle_root(tx_hashes);
}

// ---------------------------------------------------------------------------
// get_total_output_value
// ---------------------------------------------------------------------------

Amount CBlock::get_total_output_value() const {
    Amount total = 0;
    for (size_t i = 1; i < vtx.size(); ++i) {  // skip coinbase
        total += vtx[i].get_value_out();
    }
    return total;
}

// ---------------------------------------------------------------------------
// check_block -- basic structural validity
// ---------------------------------------------------------------------------

bool CBlock::check_block() const {
    // Must have at least one transaction (the coinbase).
    if (vtx.empty()) return false;

    // First transaction must be coinbase.
    if (!vtx[0].is_coinbase()) return false;

    // No other transaction may be coinbase.
    for (size_t i = 1; i < vtx.size(); ++i) {
        if (vtx[i].is_coinbase()) return false;
    }

    // Check block size limit.
    size_t block_size = get_block_size();
    if (block_size > consensus::MAX_BLOCK_SIZE) return false;

    // Check each transaction for basic validity.
    for (const auto& tx : vtx) {
        if (!tx.check_transaction()) return false;
    }

    // Verify merkle root.
    if (!verify_merkle_root()) return false;

    // Check for duplicate transactions.
    std::vector<uint256> txids;
    txids.reserve(vtx.size());
    for (const auto& tx : vtx) {
        uint256 txid = tx.get_txid();
        for (const auto& existing : txids) {
            if (txid == existing) return false;
        }
        txids.push_back(txid);
    }

    return true;
}

// ---------------------------------------------------------------------------
// to_string
// ---------------------------------------------------------------------------

std::string CBlock::to_string() const {
    std::ostringstream ss;
    ss << "CBlock(hash=" << get_hash_hex()
       << " height=" << height
       << " txs=" << vtx.size()
       << " size=" << get_block_size()
       << " delta=" << delta_payload.size()
       << " val_loss=" << val_loss
       << ")";
    return ss.str();
}

// ===========================================================================
// CBlockLocator
// ===========================================================================

std::vector<uint8_t> CBlockLocator::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(4 + 9 + hashes.size() * 32);

    // Protocol version (4 bytes LE)
    append_u32(buf, consensus::PROTOCOL_VERSION);

    // Hash count (CompactSize)
    CompactSize::encode_to(hashes.size(), buf);

    // Hashes
    for (const auto& h : hashes) {
        append_bytes(buf, h.data(), 32);
    }

    return buf;
}

bool CBlockLocator::deserialize(const uint8_t* data, size_t len) {
    if (len < 4) return false;

    // Skip version
    size_t pos = 4;

    // Hash count
    uint64_t count = 0;
    size_t consumed = CompactSize::decode(data + pos, len - pos, count);
    if (consumed == 0) return false;
    pos += consumed;

    if (count > 100000) return false;  // sanity

    hashes.resize(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        if (pos + 32 > len) return false;
        std::memcpy(hashes[i].data(), data + pos, 32);
        pos += 32;
    }

    return true;
}

// ===========================================================================
// Free functions
// ===========================================================================

// ---------------------------------------------------------------------------
// build_locator -- exponential step-back locator
// ---------------------------------------------------------------------------

CBlockLocator build_locator(const CBlockIndex* tip) {
    // Forward-declared CBlockIndex -- we only need ->prev and ->hash.
    // The actual struct is in chain/blockindex.h.
    //
    // Build strategy:
    //   - First 10 hashes: consecutive (every block)
    //   - After that: exponentially increasing step-back
    //   - Always end with genesis (height 0)

    std::vector<uint256> hashes;
    if (!tip) return CBlockLocator(hashes);

    const CBlockIndex* pindex = tip;
    int step = 1;
    int count = 0;

    while (pindex) {
        hashes.push_back(pindex->hash);

        // First 10 are consecutive, then exponential step-back
        if (count >= 10) {
            step *= 2;
        }
        ++count;

        // Walk back 'step' blocks
        for (int i = 0; i < step && pindex; ++i) {
            pindex = pindex->prev;
        }
    }

    return CBlockLocator(std::move(hashes));
}

// ---------------------------------------------------------------------------
// compute_block_weight
// ---------------------------------------------------------------------------

size_t compute_block_weight(const CBlockHeader& header,
                             const std::vector<CTransaction>& vtx,
                             const std::vector<uint8_t>& delta_payload) {
    (void)header;

    // Header: full weight (308 * 4 = 1232 weight units)
    size_t weight = BLOCK_HEADER_SIZE * WITNESS_SCALE_FACTOR;

    // Transaction count compact size
    weight += CompactSize::encoded_size(vtx.size()) * WITNESS_SCALE_FACTOR;

    // Each transaction: full weight
    for (const auto& tx : vtx) {
        weight += tx.get_serialize_size() * WITNESS_SCALE_FACTOR;
    }

    // Delta payload: discounted (1 weight unit per byte)
    // The compact size prefix counts at full weight
    weight += CompactSize::encoded_size(delta_payload.size()) * WITNESS_SCALE_FACTOR;
    weight += delta_payload.size();  // 1:1 weight (discount)

    return weight;
}

// ═══════════════════════════════════════════════════════════════════════════
// Block analysis
// ═══════════════════════════════════════════════════════════════════════════

CBlock::BlockAnalysis CBlock::analyze() const {
    BlockAnalysis a;

    // Header info
    a.height = height;
    a.hash = get_hash();
    a.prev_hash = prev_hash;
    a.timestamp = timestamp;

    // Difficulty
    {
        arith_uint256 target;
        arith_uint256 pow_limit;
        pow_limit.SetCompact(consensus::INITIAL_NBITS);
        if (consensus::derive_target(nbits, target) && !target.IsNull()) {
            // Approximate difficulty = powLimit / target
            a.difficulty = static_cast<double>(pow_limit.GetCompact() >> 24) /
                          static_cast<double>((nbits >> 24) > 0 ? (nbits >> 24) : 1);
        } else {
            a.difficulty = 1.0;
        }
    }

    // Transaction stats
    a.tx_count = vtx.size();
    a.total_size = get_block_size();
    a.total_weight = get_block_weight();

    a.total_output_value = 0;
    a.total_input_value = 0;
    a.total_fees = 0;
    a.coinbase_value = 0;
    a.total_sigops = 0;
    a.p2pkh_count = 0;
    a.multisig_count = 0;
    a.op_return_count = 0;

    for (size_t i = 0; i < vtx.size(); i++) {
        const CTransaction& tx = vtx[i];

        Amount out_value = tx.get_value_out();
        a.total_output_value += out_value;

        if (i == 0) {
            a.coinbase_value = out_value;
        }

        // Count inputs for input value estimation
        // (We don't have UTXO lookups here, so input value is not directly computable)

        // Sigops: each input contributes 1 sigop (Ed25519 signature verification)
        if (!tx.is_coinbase()) {
            a.total_sigops += static_cast<int>(tx.vin.size());
        }

        // Transaction type classification
        // P2PKH: standard single-input, single/multi-output
        if (!tx.is_coinbase()) {
            if (tx.vin.size() >= 2) {
                // Multiple inputs might indicate consolidated inputs
                a.p2pkh_count++;
            } else {
                a.p2pkh_count++;
            }
        }

        // Check for OP_RETURN-like outputs (zero-value outputs)
        for (const auto& out : tx.vout) {
            if (out.amount == 0) {
                a.op_return_count++;
            }
        }
    }

    // Training info
    a.val_loss = val_loss;
    a.d_model = d_model;
    a.n_layers = n_layers;
    a.n_slots = n_slots;
    a.model_params = consensus::estimate_param_count(d_model, n_layers, d_ff, n_slots);
    a.delta_size_compressed = delta_payload.size();

    // Estimate uncompressed delta size from sparse_count
    a.delta_size_uncompressed = static_cast<size_t>(sparse_count) * sizeof(float);
    if (a.delta_size_uncompressed == 0 && !delta_payload.empty()) {
        // If sparse_count is zero but we have a payload, approximate
        a.delta_size_uncompressed = delta_payload.size() * 2;
    }

    // Delta sparsity: ratio of non-zero elements to total parameters
    if (a.model_params > 0) {
        a.delta_sparsity = 1.0f - (static_cast<float>(sparse_count) /
                                    static_cast<float>(a.model_params));
    } else {
        a.delta_sparsity = 1.0f;
    }

    // Time since previous block (unknown without context, set to 0)
    a.time_since_prev = 0;

    return a;
}

// ═══════════════════════════════════════════════════════════════════════════
// Block comparison (for fork analysis)
// ═══════════════════════════════════════════════════════════════════════════

CBlock::BlockDiff CBlock::compare(const CBlock& a, const CBlock& b) {
    BlockDiff diff;
    diff.same_height = (a.height == b.height);
    diff.same_prev = (a.prev_hash == b.prev_hash);

    // Compare transaction sets
    std::vector<uint256> txids_a;
    txids_a.reserve(a.vtx.size());
    for (const auto& tx : a.vtx) {
        txids_a.push_back(tx.get_txid());
    }

    std::vector<uint256> txids_b;
    txids_b.reserve(b.vtx.size());
    for (const auto& tx : b.vtx) {
        txids_b.push_back(tx.get_txid());
    }

    // Sort for set operations
    std::sort(txids_a.begin(), txids_a.end());
    std::sort(txids_b.begin(), txids_b.end());

    // Count shared transactions
    diff.shared_tx_count = 0;
    size_t ia = 0, ib = 0;
    while (ia < txids_a.size() && ib < txids_b.size()) {
        if (txids_a[ia] == txids_b[ib]) {
            diff.shared_tx_count++;
            ia++;
            ib++;
        } else if (txids_a[ia] < txids_b[ib]) {
            ia++;
        } else {
            ib++;
        }
    }

    diff.unique_a_count = static_cast<int>(txids_a.size()) - diff.shared_tx_count;
    diff.unique_b_count = static_cast<int>(txids_b.size()) - diff.shared_tx_count;
    diff.same_txs = (diff.unique_a_count == 0 && diff.unique_b_count == 0);
    diff.val_loss_diff = a.val_loss - b.val_loss;

    return diff;
}

// ═══════════════════════════════════════════════════════════════════════════
// Coinbase creation helpers
// ═══════════════════════════════════════════════════════════════════════════

CTransaction CBlock::create_coinbase(uint64_t cb_height, Amount reward,
                                       const std::array<uint8_t, 32>& miner_pubkey,
                                       const std::string& extra_data) {
    // Delegate to existing make_coinbase
    return CBlock::make_coinbase(cb_height, reward, miner_pubkey, extra_data);
}

CTransaction CBlock::create_coinbase_multi(
        uint64_t cb_height, Amount reward,
        const std::vector<std::pair<std::array<uint8_t, 32>, Amount>>& payees) {

    CTransaction coinbase;
    coinbase.version = 1;
    coinbase.locktime = 0;

    // Coinbase input: null prevout
    CTxIn cb_in;
    cb_in.prevout = COutPoint();

    // Encode height in the coinbase pubkey field (BIP34 style)
    std::memset(cb_in.pubkey.data(), 0, 32);
    for (int i = 0; i < 8; ++i) {
        cb_in.pubkey[i] = static_cast<uint8_t>(cb_height >> (i * 8));
    }
    std::memset(cb_in.signature.data(), 0, 64);

    coinbase.vin.push_back(cb_in);

    // Validate: sum of payee amounts must not exceed reward
    Amount total_allocated = 0;
    for (const auto& payee : payees) {
        if (payee.second <= 0) continue;
        total_allocated += payee.second;
    }

    if (total_allocated > reward) {
        // Scale down proportionally
        for (const auto& payee : payees) {
            if (payee.second <= 0) continue;

            CTxOut out;
            double ratio = static_cast<double>(payee.second) /
                          static_cast<double>(total_allocated);
            out.amount = static_cast<Amount>(static_cast<double>(reward) * ratio);

            // Compute pubkey_hash = keccak256(pubkey)
            uint256 pkh = keccak256(payee.first.data(), 32);
            std::memcpy(out.pubkey_hash.data(), pkh.data(), 32);
            coinbase.vout.push_back(out);
        }
    } else {
        // Allocate as specified
        Amount remaining = reward;

        for (size_t i = 0; i < payees.size(); i++) {
            const auto& payee = payees[i];
            if (payee.second <= 0) continue;

            CTxOut out;

            if (i == payees.size() - 1) {
                // Last payee gets the remainder (avoids rounding errors)
                out.amount = remaining;
            } else {
                out.amount = payee.second;
                remaining -= payee.second;
            }

            uint256 pkh = keccak256(payee.first.data(), 32);
            std::memcpy(out.pubkey_hash.data(), pkh.data(), 32);
            coinbase.vout.push_back(out);
        }
    }

    return coinbase;
}

// ═══════════════════════════════════════════════════════════════════════════
// Merkle proof generation and verification
// ═══════════════════════════════════════════════════════════════════════════

CBlock::MerkleProof CBlock::get_tx_proof(uint32_t tx_index) const {
    MerkleProof proof;

    if (tx_index >= vtx.size()) {
        return proof;
    }

    // Compute all transaction hashes
    std::vector<uint256> hashes;
    hashes.reserve(vtx.size());
    for (const auto& tx : vtx) {
        hashes.push_back(tx.get_txid());
    }

    proof.txid = hashes[tx_index];
    proof.root = merkle_root;
    proof.index = tx_index;

    // Build merkle tree and extract proof branch
    // The merkle tree is built bottom-up by pairwise hashing.
    // For each level, we record which sibling hash is needed.

    std::vector<uint256> level = hashes;
    uint32_t idx = tx_index;

    while (level.size() > 1) {
        // If odd number, duplicate the last element
        if (level.size() % 2 != 0) {
            level.push_back(level.back());
        }

        // Record the sibling of the current index
        uint32_t sibling_idx;
        if (idx % 2 == 0) {
            sibling_idx = idx + 1;
        } else {
            sibling_idx = idx - 1;
        }

        if (sibling_idx < level.size()) {
            proof.branch.push_back(level[sibling_idx]);
        }

        // Move to the next level
        std::vector<uint256> next_level;
        next_level.reserve(level.size() / 2);

        for (size_t i = 0; i < level.size(); i += 2) {
            // Hash pair: keccak256(left || right)
            std::vector<uint8_t> combined;
            combined.reserve(64);
            combined.insert(combined.end(),
                             level[i].begin(), level[i].end());
            combined.insert(combined.end(),
                             level[i + 1].begin(), level[i + 1].end());
            next_level.push_back(keccak256(combined.data(), combined.size()));
        }

        idx = idx / 2;
        level = std::move(next_level);
    }

    return proof;
}

bool CBlock::MerkleProof::verify() const {
    if (branch.empty() && root == txid) {
        return true;  // Single-transaction tree
    }

    uint256 current = txid;
    uint32_t idx = index;

    for (const auto& sibling : branch) {
        std::vector<uint8_t> combined;
        combined.reserve(64);

        if (idx % 2 == 0) {
            // Current is left child
            combined.insert(combined.end(), current.begin(), current.end());
            combined.insert(combined.end(), sibling.begin(), sibling.end());
        } else {
            // Current is right child
            combined.insert(combined.end(), sibling.begin(), sibling.end());
            combined.insert(combined.end(), current.begin(), current.end());
        }

        current = keccak256(combined.data(), combined.size());
        idx = idx / 2;
    }

    return current == root;
}

std::vector<uint8_t> CBlock::MerkleProof::serialize() const {
    std::vector<uint8_t> out;

    // txid (32 bytes)
    out.insert(out.end(), txid.begin(), txid.end());

    // root (32 bytes)
    out.insert(out.end(), root.begin(), root.end());

    // index (4 bytes LE)
    append_u32(out, index);

    // branch count (4 bytes LE)
    append_u32(out, static_cast<uint32_t>(branch.size()));

    // branch hashes (32 bytes each)
    for (const auto& h : branch) {
        append_bytes(out, h.data(), 32);
    }

    return out;
}

CBlock::MerkleProof CBlock::MerkleProof::deserialize(
        const uint8_t* data, size_t len) {
    MerkleProof proof;

    // Minimum: 32 (txid) + 32 (root) + 4 (index) + 4 (count) = 72
    if (len < 72) return proof;

    size_t pos = 0;

    std::memcpy(proof.txid.data(), data + pos, 32);
    pos += 32;

    std::memcpy(proof.root.data(), data + pos, 32);
    pos += 32;

    proof.index = read_u32_le(data + pos);
    pos += 4;

    uint32_t count = read_u32_le(data + pos);
    pos += 4;

    if (count > 256) return proof;  // sanity check
    if (pos + count * 32 > len) return proof;

    proof.branch.resize(count);
    for (uint32_t i = 0; i < count; i++) {
        std::memcpy(proof.branch[i].data(), data + pos, 32);
        pos += 32;
    }

    return proof;
}

bool CBlock::verify_tx_proof(const MerkleProof& proof) const {
    // Verify the proof resolves to our merkle root
    if (proof.root != merkle_root) return false;
    return proof.verify();
}

} // namespace flow
