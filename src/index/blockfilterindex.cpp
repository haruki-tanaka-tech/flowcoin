// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "index/blockfilterindex.h"
#include "hash/keccak.h"
#include "util/strencodings.h"

#include <sqlite3.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <numeric>

namespace flow {

// ============================================================================
// Filter type name
// ============================================================================

const char* block_filter_type_name(BlockFilterType type) {
    switch (type) {
        case BlockFilterType::BASIC: return "basic";
    }
    return "unknown";
}

// ============================================================================
// GCS namespace utilities
// ============================================================================

namespace gcs {

// ----------------------------------------------------------------------------
// SipHash-2-4 implementation
// ----------------------------------------------------------------------------

static inline uint64_t rotl64(uint64_t v, int n) {
    return (v << n) | (v >> (64 - n));
}

static inline void sip_round(uint64_t& v0, uint64_t& v1,
                              uint64_t& v2, uint64_t& v3) {
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0;
    v0 = rotl64(v0, 32);
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2;
    v2 = rotl64(v2, 32);
}

SipHashKey derive_key(const uint256& block_hash) {
    SipHashKey key;
    std::memcpy(&key.k0, block_hash.data(), 8);
    std::memcpy(&key.k1, block_hash.data() + 8, 8);
    return key;
}

uint64_t siphash(uint64_t k0, uint64_t k1,
                 const uint8_t* data, size_t len) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t* end = data + (len & ~7ULL);
    const int left = static_cast<int>(len & 7);

    for (const uint8_t* p = data; p != end; p += 8) {
        uint64_t m;
        std::memcpy(&m, p, 8);
        v3 ^= m;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= m;
    }

    uint64_t b = static_cast<uint64_t>(len) << 56;
    switch (left) {
        case 7: b |= static_cast<uint64_t>(end[6]) << 48; [[fallthrough]];
        case 6: b |= static_cast<uint64_t>(end[5]) << 40; [[fallthrough]];
        case 5: b |= static_cast<uint64_t>(end[4]) << 32; [[fallthrough]];
        case 4: b |= static_cast<uint64_t>(end[3]) << 24; [[fallthrough]];
        case 3: b |= static_cast<uint64_t>(end[2]) << 16; [[fallthrough]];
        case 2: b |= static_cast<uint64_t>(end[1]) << 8;  [[fallthrough]];
        case 1: b |= static_cast<uint64_t>(end[0]);        break;
        case 0: break;
    }

    v3 ^= b;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xff;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

// ----------------------------------------------------------------------------
// GCSFilter
// ----------------------------------------------------------------------------

GCSFilter::GCSFilter() = default;

uint64_t GCSFilter::hash_element(const std::vector<uint8_t>& element) const {
    return hash_raw(element.data(), element.size());
}

uint64_t GCSFilter::hash_raw(const uint8_t* data, size_t len) const {
    uint64_t h = siphash(key_.k0, key_.k1, data, len);
    // Map to [0, n*M) using fixed-point multiplication
    // result = (h * (n * M)) >> 64, done via __uint128_t
    __uint128_t product = static_cast<__uint128_t>(h) *
                          static_cast<__uint128_t>(n_ * M);
    return static_cast<uint64_t>(product >> 64);
}

void GCSFilter::build(const std::vector<std::vector<uint8_t>>& elements,
                      const uint256& block_hash) {
    key_ = derive_key(block_hash);
    n_ = elements.size();

    if (n_ == 0) {
        sorted_hashed_.clear();
        encoded_.clear();
        return;
    }

    // Hash all elements
    sorted_hashed_.resize(n_);
    for (size_t i = 0; i < n_; ++i) {
        sorted_hashed_[i] = hash_element(elements[i]);
    }

    // Sort and deduplicate
    std::sort(sorted_hashed_.begin(), sorted_hashed_.end());
    auto last = std::unique(sorted_hashed_.begin(), sorted_hashed_.end());
    sorted_hashed_.erase(last, sorted_hashed_.end());
    n_ = sorted_hashed_.size();

    // Encode deltas using Golomb-Rice
    encode_deltas();
}

bool GCSFilter::match(const std::vector<uint8_t>& element) const {
    if (n_ == 0) return false;

    uint64_t h = hash_element(element);
    return std::binary_search(sorted_hashed_.begin(), sorted_hashed_.end(), h);
}

bool GCSFilter::match_any(
    const std::vector<std::vector<uint8_t>>& elements) const {
    if (n_ == 0 || elements.empty()) return false;

    // Hash and sort the test elements
    std::vector<uint64_t> test_hashed;
    test_hashed.reserve(elements.size());
    for (const auto& elem : elements) {
        test_hashed.push_back(hash_element(elem));
    }
    std::sort(test_hashed.begin(), test_hashed.end());

    // Merge-intersect with sorted_hashed_ (both are sorted)
    size_t i = 0, j = 0;
    while (i < sorted_hashed_.size() && j < test_hashed.size()) {
        if (sorted_hashed_[i] == test_hashed[j]) {
            return true;
        } else if (sorted_hashed_[i] < test_hashed[j]) {
            ++i;
        } else {
            ++j;
        }
    }

    return false;
}

std::vector<uint8_t> GCSFilter::encode() const {
    // Format: n (varint) || encoded_data
    std::vector<uint8_t> result;

    // Encode n as a simple 8-byte LE value
    uint64_t count = n_;
    for (int i = 0; i < 8; ++i) {
        result.push_back(static_cast<uint8_t>(count & 0xFF));
        count >>= 8;
    }

    // Append Golomb-Rice encoded data
    result.insert(result.end(), encoded_.begin(), encoded_.end());
    return result;
}

bool GCSFilter::decode(const std::vector<uint8_t>& data,
                       const uint256& block_hash) {
    if (data.size() < 8) return false;

    key_ = derive_key(block_hash);

    // Read n
    n_ = 0;
    for (int i = 7; i >= 0; --i) {
        n_ = (n_ << 8) | data[i];
    }

    if (n_ > MAX_FILTER_ELEMENTS) return false;
    if (n_ == 0) {
        sorted_hashed_.clear();
        encoded_.clear();
        return true;
    }

    // Store encoded data
    encoded_.assign(data.begin() + 8, data.end());

    // Decode deltas to reconstruct sorted_hashed_
    return decode_deltas(encoded_.data(), encoded_.size());
}

size_t GCSFilter::serialized_size() const {
    return 8 + encoded_.size();
}

// ----------------------------------------------------------------------------
// Golomb-Rice bit I/O
// ----------------------------------------------------------------------------

void GCSFilter::write_bit(std::vector<uint8_t>& out,
                           size_t& bit_pos, bool bit) {
    size_t byte_idx = bit_pos / 8;
    size_t bit_idx = bit_pos % 8;

    if (byte_idx >= out.size()) {
        out.push_back(0);
    }

    if (bit) {
        out[byte_idx] |= (1u << (7 - bit_idx));
    }

    ++bit_pos;
}

void GCSFilter::write_bits(std::vector<uint8_t>& out,
                            size_t& bit_pos, uint64_t value, int n_bits) {
    for (int i = n_bits - 1; i >= 0; --i) {
        write_bit(out, bit_pos, (value >> i) & 1);
    }
}

bool GCSFilter::read_bit(const uint8_t* data,
                          size_t& bit_pos, size_t data_len) {
    size_t byte_idx = bit_pos / 8;
    size_t bit_idx = bit_pos % 8;

    if (byte_idx >= data_len) return false;

    bool result = (data[byte_idx] >> (7 - bit_idx)) & 1;
    ++bit_pos;
    return result;
}

uint64_t GCSFilter::read_bits(const uint8_t* data,
                               size_t& bit_pos, int n_bits, size_t data_len) {
    uint64_t result = 0;
    for (int i = 0; i < n_bits; ++i) {
        result = (result << 1) | (read_bit(data, bit_pos, data_len) ? 1 : 0);
    }
    return result;
}

// ----------------------------------------------------------------------------
// Golomb-Rice encoding/decoding
// ----------------------------------------------------------------------------

void GCSFilter::golomb_encode(std::vector<uint8_t>& out,
                               size_t& bit_pos, uint64_t value) {
    uint64_t quotient = value >> P;
    uint64_t remainder = value & ((1ULL << P) - 1);

    // Unary encode the quotient: quotient 1-bits followed by a 0-bit
    for (uint64_t i = 0; i < quotient; ++i) {
        write_bit(out, bit_pos, true);
    }
    write_bit(out, bit_pos, false);

    // Binary encode the remainder in P bits
    write_bits(out, bit_pos, remainder, P);
}

uint64_t GCSFilter::golomb_decode(const uint8_t* data,
                                   size_t& bit_pos, size_t data_len) {
    // Decode unary quotient
    uint64_t quotient = 0;
    while (read_bit(data, bit_pos, data_len)) {
        ++quotient;
        if (quotient > 1000000) break;  // sanity limit
    }

    // Decode P-bit remainder
    uint64_t remainder = read_bits(data, bit_pos, P, data_len);

    return (quotient << P) | remainder;
}

void GCSFilter::encode_deltas() {
    encoded_.clear();
    if (n_ == 0) return;

    // Reserve a reasonable amount of space
    encoded_.reserve(n_ * 3);

    size_t bit_pos = 0;
    uint64_t prev = 0;

    for (size_t i = 0; i < n_; ++i) {
        uint64_t delta = sorted_hashed_[i] - prev;
        golomb_encode(encoded_, bit_pos, delta);
        prev = sorted_hashed_[i];
    }

    // Trim to actual byte count
    size_t byte_count = (bit_pos + 7) / 8;
    encoded_.resize(byte_count);
}

bool GCSFilter::decode_deltas(const uint8_t* data, size_t len) {
    sorted_hashed_.clear();
    sorted_hashed_.reserve(n_);

    if (n_ == 0) return true;
    if (len == 0) return false;

    size_t bit_pos = 0;
    uint64_t prev = 0;

    for (uint64_t i = 0; i < n_; ++i) {
        uint64_t delta = golomb_decode(data, bit_pos, len);
        uint64_t value = prev + delta;
        sorted_hashed_.push_back(value);
        prev = value;
    }

    return true;
}

} // namespace gcs

// ============================================================================
// BlockFilter
// ============================================================================

BlockFilter BlockFilter::compute_basic(const CBlock& block) {
    BlockFilter bf;
    bf.type = BlockFilterType::BASIC;
    bf.block_hash = block.get_hash();

    // Collect filter elements: all output pubkey hashes + spent outpoints
    std::vector<std::vector<uint8_t>> elements;

    for (const auto& tx : block.vtx) {
        // Add all output pubkey hashes
        for (const auto& out : tx.vout) {
            if (out.amount <= 0) continue;  // skip OP_RETURN / zero outputs

            std::vector<uint8_t> elem(out.pubkey_hash.begin(),
                                       out.pubkey_hash.end());
            if (!elem.empty()) {
                elements.push_back(std::move(elem));
            }
        }

        // Add spent outpoints (for non-coinbase inputs)
        if (!tx.is_coinbase()) {
            for (const auto& in : tx.vin) {
                std::vector<uint8_t> outpoint_data = in.prevout.serialize();
                elements.push_back(std::move(outpoint_data));
            }
        }
    }

    // Build the GCS filter
    bf.filter.build(elements, bf.block_hash);

    // Compute filter hash
    bf.compute_hash();

    return bf;
}

void BlockFilter::compute_hash() {
    std::vector<uint8_t> encoded = filter.encode();
    filter_hash = keccak256d(encoded);
}

std::vector<uint8_t> BlockFilter::serialize() const {
    // Format: type (1 byte) || block_hash (32 bytes) || filter_hash (32 bytes)
    //         || filter_data_len (4 bytes LE) || filter_data
    std::vector<uint8_t> result;
    result.reserve(1 + 32 + 32 + 4 + filter.serialized_size());

    // Type
    result.push_back(static_cast<uint8_t>(type));

    // Block hash
    result.insert(result.end(), block_hash.begin(), block_hash.end());

    // Filter hash
    result.insert(result.end(), filter_hash.begin(), filter_hash.end());

    // Filter data
    std::vector<uint8_t> fdata = filter.encode();
    uint32_t flen = static_cast<uint32_t>(fdata.size());
    result.push_back(static_cast<uint8_t>(flen & 0xFF));
    result.push_back(static_cast<uint8_t>((flen >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>((flen >> 16) & 0xFF));
    result.push_back(static_cast<uint8_t>((flen >> 24) & 0xFF));
    result.insert(result.end(), fdata.begin(), fdata.end());

    return result;
}

bool BlockFilter::deserialize(const std::vector<uint8_t>& data,
                               const uint256& block_hash_in,
                               BlockFilterType type_in) {
    if (data.size() < 1 + 32 + 32 + 4) return false;

    size_t pos = 0;

    // Type
    type = static_cast<BlockFilterType>(data[pos++]);
    if (type != type_in) return false;

    // Block hash
    std::memcpy(block_hash.data(), &data[pos], 32);
    pos += 32;
    if (block_hash != block_hash_in) return false;

    // Filter hash
    std::memcpy(filter_hash.data(), &data[pos], 32);
    pos += 32;

    // Filter data length
    if (pos + 4 > data.size()) return false;
    uint32_t flen = 0;
    flen |= static_cast<uint32_t>(data[pos++]);
    flen |= static_cast<uint32_t>(data[pos++]) << 8;
    flen |= static_cast<uint32_t>(data[pos++]) << 16;
    flen |= static_cast<uint32_t>(data[pos++]) << 24;

    if (pos + flen > data.size()) return false;

    // Decode filter
    std::vector<uint8_t> fdata(data.begin() + pos, data.begin() + pos + flen);
    if (!filter.decode(fdata, block_hash)) return false;

    // Verify filter hash
    uint256 computed_hash = keccak256d(fdata);
    return computed_hash == filter_hash;
}

// ============================================================================
// BlockFilterIndex
// ============================================================================

BlockFilterIndex::BlockFilterIndex(const std::string& db_path,
                                   BlockFilterType type)
    : BaseIndex("blockfilterindex", db_path), type_(type) {
}

BlockFilterIndex::~BlockFilterIndex() {
    finalize_statements();
}

// ============================================================================
// Database initialization
// ============================================================================

bool BlockFilterIndex::init_db() {
    const char* create_table =
        "CREATE TABLE IF NOT EXISTS block_filters ("
        "  block_hash BLOB NOT NULL,"
        "  block_height INTEGER NOT NULL,"
        "  filter_type INTEGER NOT NULL,"
        "  filter_data BLOB NOT NULL,"
        "  filter_hash BLOB NOT NULL,"
        "  filter_header BLOB NOT NULL,"
        "  PRIMARY KEY (block_hash, filter_type)"
        ")";
    if (!exec_sql(create_table)) return false;

    const char* height_idx =
        "CREATE INDEX IF NOT EXISTS idx_bf_height "
        "ON block_filters(block_height, filter_type)";
    if (!exec_sql(height_idx)) return false;

    prepare_statements();

    // Load previous filter header for chain continuity
    uint64_t best = load_best_height();
    if (best > 0) {
        load_prev_filter_header(best);
    }

    return true;
}

void BlockFilterIndex::prepare_statements() {
    if (!db_) return;

    const char* insert_sql =
        "INSERT OR REPLACE INTO block_filters "
        "(block_hash, block_height, filter_type, filter_data, "
        "filter_hash, filter_header) "
        "VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_prepare_v2(db_, insert_sql, -1, &stmt_insert_, nullptr);

    const char* find_by_hash_sql =
        "SELECT filter_data, filter_hash, filter_header, block_height "
        "FROM block_filters WHERE block_hash = ? AND filter_type = ?";
    sqlite3_prepare_v2(db_, find_by_hash_sql, -1, &stmt_find_by_hash_, nullptr);

    const char* find_by_height_sql =
        "SELECT block_hash, filter_data, filter_hash, filter_header "
        "FROM block_filters WHERE block_height = ? AND filter_type = ?";
    sqlite3_prepare_v2(db_, find_by_height_sql, -1, &stmt_find_by_height_, nullptr);

    const char* header_sql =
        "SELECT filter_header FROM block_filters "
        "WHERE block_hash = ? AND filter_type = ?";
    sqlite3_prepare_v2(db_, header_sql, -1, &stmt_header_by_hash_, nullptr);

    const char* headers_range_sql =
        "SELECT filter_header FROM block_filters "
        "WHERE block_height >= ? AND block_height < ? AND filter_type = ? "
        "ORDER BY block_height";
    sqlite3_prepare_v2(db_, headers_range_sql, -1, &stmt_headers_range_, nullptr);

    const char* delete_sql =
        "DELETE FROM block_filters WHERE block_height = ? AND filter_type = ?";
    sqlite3_prepare_v2(db_, delete_sql, -1, &stmt_delete_, nullptr);

    const char* count_sql =
        "SELECT COUNT(*) FROM block_filters WHERE filter_type = ?";
    sqlite3_prepare_v2(db_, count_sql, -1, &stmt_count_, nullptr);

    const char* has_sql =
        "SELECT 1 FROM block_filters "
        "WHERE block_hash = ? AND filter_type = ? LIMIT 1";
    sqlite3_prepare_v2(db_, has_sql, -1, &stmt_has_, nullptr);

    const char* prev_header_sql =
        "SELECT filter_header FROM block_filters "
        "WHERE block_height = ? AND filter_type = ?";
    sqlite3_prepare_v2(db_, prev_header_sql, -1, &stmt_prev_header_, nullptr);
}

void BlockFilterIndex::finalize_statements() {
    auto fin = [](sqlite3_stmt*& s) {
        if (s) { sqlite3_finalize(s); s = nullptr; }
    };
    fin(stmt_insert_);
    fin(stmt_find_by_hash_);
    fin(stmt_find_by_height_);
    fin(stmt_header_by_hash_);
    fin(stmt_headers_range_);
    fin(stmt_delete_);
    fin(stmt_count_);
    fin(stmt_has_);
    fin(stmt_prev_header_);
}

// ============================================================================
// Write / undo
// ============================================================================

uint256 BlockFilterIndex::compute_filter_header(
    const uint256& filter_hash, const uint256& prev_header) const {
    // filter_header = keccak256d(filter_hash || prev_filter_header)
    std::vector<uint8_t> data;
    data.reserve(64);
    data.insert(data.end(), filter_hash.begin(), filter_hash.end());
    data.insert(data.end(), prev_header.begin(), prev_header.end());
    return keccak256d(data);
}

std::vector<std::vector<uint8_t>> BlockFilterIndex::get_basic_filter_elements(
    const CBlock& block) const {
    std::vector<std::vector<uint8_t>> elements;

    for (const auto& tx : block.vtx) {
        // Output pubkey hashes
        for (const auto& out : tx.vout) {
            if (out.amount <= 0) continue;
            std::vector<uint8_t> elem(out.pubkey_hash.begin(),
                                       out.pubkey_hash.end());
            elements.push_back(std::move(elem));
        }

        // Spent outpoints (non-coinbase)
        if (!tx.is_coinbase()) {
            for (const auto& in : tx.vin) {
                std::vector<uint8_t> op_data = in.prevout.serialize();
                elements.push_back(std::move(op_data));
            }
        }
    }

    return elements;
}

bool BlockFilterIndex::write_block(const CBlock& block, uint64_t height) {
    if (!stmt_insert_) return false;

    uint256 block_hash = block.get_hash();

    // Build the filter
    auto elements = get_basic_filter_elements(block);

    gcs::GCSFilter gcs_filter;
    gcs_filter.build(elements, block_hash);

    // Encode and hash the filter
    std::vector<uint8_t> filter_data = gcs_filter.encode();
    uint256 filter_hash = keccak256d(filter_data);

    // Compute filter header
    uint256 filter_header = compute_filter_header(filter_hash, prev_filter_header_);

    // Store in database
    sqlite3_reset(stmt_insert_);

    sqlite3_bind_blob(stmt_insert_, 1,
                      block_hash.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt_insert_, 2, static_cast<int64_t>(height));
    sqlite3_bind_int(stmt_insert_, 3, static_cast<int>(type_));
    sqlite3_bind_blob(stmt_insert_, 4,
                      filter_data.data(), static_cast<int>(filter_data.size()),
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt_insert_, 5,
                      filter_hash.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt_insert_, 6,
                      filter_header.data(), 32, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_insert_);
    if (rc != SQLITE_DONE) return false;

    // Update running header for next block
    prev_filter_header_ = filter_header;

    return true;
}

bool BlockFilterIndex::undo_block(const CBlock& /*block*/, uint64_t height) {
    if (!stmt_delete_) return false;

    // Load the filter header of the previous block to restore the chain
    if (height > 0) {
        load_prev_filter_header(height - 1);
    } else {
        prev_filter_header_.set_null();
    }

    sqlite3_reset(stmt_delete_);
    sqlite3_bind_int64(stmt_delete_, 1, static_cast<int64_t>(height));
    sqlite3_bind_int(stmt_delete_, 2, static_cast<int>(type_));

    int rc = sqlite3_step(stmt_delete_);
    return rc == SQLITE_DONE;
}

bool BlockFilterIndex::load_prev_filter_header(uint64_t height) {
    if (!stmt_prev_header_) return false;

    sqlite3_reset(stmt_prev_header_);
    sqlite3_bind_int64(stmt_prev_header_, 1, static_cast<int64_t>(height));
    sqlite3_bind_int(stmt_prev_header_, 2, static_cast<int>(type_));

    int rc = sqlite3_step(stmt_prev_header_);
    if (rc == SQLITE_ROW) {
        const void* data = sqlite3_column_blob(stmt_prev_header_, 0);
        int len = sqlite3_column_bytes(stmt_prev_header_, 0);
        if (data && len == 32) {
            std::memcpy(prev_filter_header_.data(), data, 32);
            return true;
        }
    }

    prev_filter_header_.set_null();
    return false;
}

// ============================================================================
// Lookups
// ============================================================================

bool BlockFilterIndex::get_filter(const uint256& block_hash,
                                   BlockFilter& filter_out) const {
    if (!stmt_find_by_hash_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_find_by_hash_);
    sqlite3_bind_blob(stmt_find_by_hash_, 1, block_hash.data(), 32,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt_find_by_hash_, 2, static_cast<int>(type_));

    int rc = sqlite3_step(stmt_find_by_hash_);
    if (rc != SQLITE_ROW) return false;

    filter_out.type = type_;
    filter_out.block_hash = block_hash;

    // filter_data
    const void* fd = sqlite3_column_blob(stmt_find_by_hash_, 0);
    int fd_len = sqlite3_column_bytes(stmt_find_by_hash_, 0);
    if (fd && fd_len > 0) {
        std::vector<uint8_t> fdata(static_cast<const uint8_t*>(fd),
                                    static_cast<const uint8_t*>(fd) + fd_len);
        filter_out.filter.decode(fdata, block_hash);
    }

    // filter_hash
    const void* fh = sqlite3_column_blob(stmt_find_by_hash_, 1);
    int fh_len = sqlite3_column_bytes(stmt_find_by_hash_, 1);
    if (fh && fh_len == 32) {
        std::memcpy(filter_out.filter_hash.data(), fh, 32);
    }

    return true;
}

bool BlockFilterIndex::get_filter_at_height(uint64_t height,
                                             BlockFilter& filter_out) const {
    if (!stmt_find_by_height_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_find_by_height_);
    sqlite3_bind_int64(stmt_find_by_height_, 1, static_cast<int64_t>(height));
    sqlite3_bind_int(stmt_find_by_height_, 2, static_cast<int>(type_));

    int rc = sqlite3_step(stmt_find_by_height_);
    if (rc != SQLITE_ROW) return false;

    // block_hash
    const void* bh = sqlite3_column_blob(stmt_find_by_height_, 0);
    int bh_len = sqlite3_column_bytes(stmt_find_by_height_, 0);
    if (bh && bh_len == 32) {
        std::memcpy(filter_out.block_hash.data(), bh, 32);
    }

    filter_out.type = type_;

    // filter_data
    const void* fd = sqlite3_column_blob(stmt_find_by_height_, 1);
    int fd_len = sqlite3_column_bytes(stmt_find_by_height_, 1);
    if (fd && fd_len > 0) {
        std::vector<uint8_t> fdata(static_cast<const uint8_t*>(fd),
                                    static_cast<const uint8_t*>(fd) + fd_len);
        filter_out.filter.decode(fdata, filter_out.block_hash);
    }

    // filter_hash
    const void* fh = sqlite3_column_blob(stmt_find_by_height_, 2);
    int fh_len = sqlite3_column_bytes(stmt_find_by_height_, 2);
    if (fh && fh_len == 32) {
        std::memcpy(filter_out.filter_hash.data(), fh, 32);
    }

    return true;
}

bool BlockFilterIndex::get_filter_header(const uint256& block_hash,
                                          uint256& header_out) const {
    if (!stmt_header_by_hash_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_header_by_hash_);
    sqlite3_bind_blob(stmt_header_by_hash_, 1, block_hash.data(), 32,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt_header_by_hash_, 2, static_cast<int>(type_));

    int rc = sqlite3_step(stmt_header_by_hash_);
    if (rc != SQLITE_ROW) return false;

    const void* data = sqlite3_column_blob(stmt_header_by_hash_, 0);
    int len = sqlite3_column_bytes(stmt_header_by_hash_, 0);
    if (!data || len != 32) return false;

    std::memcpy(header_out.data(), data, 32);
    return true;
}

std::vector<uint256> BlockFilterIndex::get_filter_headers(
    uint64_t start_height, uint64_t count) const {
    std::vector<uint256> result;
    if (!stmt_headers_range_) return result;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_headers_range_);
    sqlite3_bind_int64(stmt_headers_range_, 1,
                       static_cast<int64_t>(start_height));
    sqlite3_bind_int64(stmt_headers_range_, 2,
                       static_cast<int64_t>(start_height + count));
    sqlite3_bind_int(stmt_headers_range_, 3, static_cast<int>(type_));

    while (sqlite3_step(stmt_headers_range_) == SQLITE_ROW) {
        const void* data = sqlite3_column_blob(stmt_headers_range_, 0);
        int len = sqlite3_column_bytes(stmt_headers_range_, 0);
        if (data && len == 32) {
            uint256 header;
            std::memcpy(header.data(), data, 32);
            result.push_back(header);
        }
    }

    return result;
}

uint64_t BlockFilterIndex::count() const {
    if (!stmt_count_) return 0;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_count_);
    sqlite3_bind_int(stmt_count_, 1, static_cast<int>(type_));

    int rc = sqlite3_step(stmt_count_);
    if (rc == SQLITE_ROW) {
        return static_cast<uint64_t>(sqlite3_column_int64(stmt_count_, 0));
    }
    return 0;
}

bool BlockFilterIndex::has_filter(const uint256& block_hash) const {
    if (!stmt_has_) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_reset(stmt_has_);
    sqlite3_bind_blob(stmt_has_, 1, block_hash.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt_has_, 2, static_cast<int>(type_));

    return sqlite3_step(stmt_has_) == SQLITE_ROW;
}

} // namespace flow
