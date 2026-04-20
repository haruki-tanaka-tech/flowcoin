// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Keccak-256 and Keccak-512 hashing wrappers over XKCP.
// Uses original Keccak padding (0x01), NOT SHA-3 (0x06).

#pragma once

#include "../util/types.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "KeccakHash.h"
}

namespace flow {

// ===========================================================================
// Single-shot Keccak-256
// ===========================================================================

/** Hash arbitrary data with Keccak-256 (Ethereum-compatible, pad byte 0x01). */
uint256 keccak256(const uint8_t* data, size_t len);

/** Hash a byte vector with Keccak-256. */
uint256 keccak256(const std::vector<uint8_t>& data);

/** Hash a string with Keccak-256. */
uint256 keccak256(const std::string& data);

// ===========================================================================
// Double Keccak-256 (analogous to Bitcoin's SHA256d)
// ===========================================================================

/** Compute keccak256(keccak256(data)). */
uint256 keccak256d(const uint8_t* data, size_t len);

/** Compute keccak256(keccak256(data)). */
uint256 keccak256d(const std::vector<uint8_t>& data);

/** Compute keccak256(keccak256(data)). */
uint256 keccak256d(const std::string& data);

// ===========================================================================
// Incremental hasher
// ===========================================================================

/** Incremental Keccak-256 hasher for streaming data. */
class CKeccak256 {
public:
    CKeccak256();

    /** Feed data into the hash. Can be called multiple times. */
    void update(const uint8_t* data, size_t len);

    /** Feed a byte vector into the hash. */
    void update(const std::vector<uint8_t>& data);

    /** Feed a string into the hash. */
    void update(const std::string& data);

    /** Finalize and return the 32-byte digest. The hasher is consumed;
     *  call reset() before reusing. */
    uint256 finalize();

    /** Reset to initial state for reuse. */
    void reset();

private:
    Keccak_HashInstance state_;
};

// ===========================================================================
// Double Keccak-256 incremental hasher
// ===========================================================================

/** Incremental Keccak-256d hasher (double hash).
 *  Collects all data, then computes keccak256(keccak256(data)) on finalize.
 */
class CKeccak256D {
public:
    CKeccak256D();

    /** Feed data into the hash. */
    void update(const uint8_t* data, size_t len);

    /** Feed a byte vector into the hash. */
    void update(const std::vector<uint8_t>& data);

    /** Finalize and return the double hash. */
    uint256 finalize();

    /** Reset to initial state for reuse. */
    void reset();

private:
    CKeccak256 inner_;
};

// ===========================================================================
// Keccak-512
// ===========================================================================

/** Compute Keccak-512 hash (64 bytes output).
 *  Used internally by Ed25519 and HMAC-Keccak-512.
 */
uint512 keccak512(const uint8_t* data, size_t len);

/** Compute Keccak-512 hash of a vector. */
uint512 keccak512(const std::vector<uint8_t>& data);

// ===========================================================================
// HashWriter: serialize directly into Keccak hash
// ===========================================================================

/** A writer that feeds serialized data directly into a Keccak-256 hash.
 *  Supports operator<< for all serializable types.
 *
 *  Usage:
 *    HashWriter hw;
 *    hw << tx.version << tx.inputs << tx.outputs;
 *    uint256 hash = hw.GetHash();
 */
class HashWriter {
public:
    HashWriter();

    /** Write raw bytes. */
    void write(const uint8_t* data, size_t len);

    /** Write a byte vector. */
    void write(const std::vector<uint8_t>& data);

    /** Get the single Keccak-256 hash. */
    uint256 GetHash();

    /** Get the double Keccak-256 hash (keccak256d). */
    uint256 GetDoubleHash();

    /** Reset the writer for reuse. */
    void reset();

    // Operator<< overloads for common types

    HashWriter& operator<<(uint8_t val);
    HashWriter& operator<<(uint16_t val);
    HashWriter& operator<<(uint32_t val);
    HashWriter& operator<<(uint64_t val);
    HashWriter& operator<<(int32_t val);
    HashWriter& operator<<(int64_t val);
    HashWriter& operator<<(const uint256& val);
    HashWriter& operator<<(const uint512& val);
    HashWriter& operator<<(const std::vector<uint8_t>& val);
    HashWriter& operator<<(const std::string& val);

private:
    CKeccak256 hasher_;
};

// ===========================================================================
// Hash comparison utilities
// ===========================================================================

/** Compare a hash against a target (for PoW/PoT checks).
 *  Returns true if hash <= target.
 */
bool hash_meets_target(const uint256& hash, const uint256& target);

/** Check if a hash has at least n leading zero bits. */
bool hash_has_leading_zeros(const uint256& hash, int n_bits);

/** Count the number of leading zero bits in a hash. */
int count_leading_zeros(const uint256& hash);

} // namespace flow
