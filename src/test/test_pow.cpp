// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Unit tests for the Keccak-256d Proof-of-Work.
//
// Verifies:
//   1. CheckProofOfWork accepts a header whose keccak256d hash meets the target.
//   2. CheckProofOfWork rejects a header whose hash exceeds the target.
//   3. The PoW hash is identical to the block ID (get_hash()).

#include "consensus/pow.h"
#include "primitives/block.h"
#include "hash/keccak.h"

#include <cassert>
#include <cstring>

void test_pow() {
    using namespace flow;

    // Build a trivial header with the easiest possible target (difficulty 1).
    CBlockHeader header;
    header.height    = 0;
    header.timestamp = 1776902400;
    header.nbits     = consensus::INITIAL_NBITS;
    header.version   = 1;

    // Brute-force a nonce that satisfies the easiest target.
    // With Keccak-256d and INITIAL_NBITS = 0x1d00ffff this should be fast.
    bool found = false;
    for (uint32_t nonce = 0; nonce < 0xFFFFFFFF; ++nonce) {
        header.nonce = nonce;
        if (consensus::CheckProofOfWork(header)) {
            found = true;
            break;
        }
    }
    assert(found && "should find a valid nonce at difficulty 1");

    // The PoW hash IS the block ID.
    uint256 block_id = header.get_hash();
    auto unsigned_data = header.get_unsigned_data();
    uint256 manual_hash = keccak256d(unsigned_data.data(), unsigned_data.size());
    assert(block_id == manual_hash);

    // Changing the nonce to something invalid should fail CheckProofOfWork.
    // (We just set nbits to an impossibly hard target so any hash fails.)
    CBlockHeader hard = header;
    hard.nbits = 0x03000001;  // target = 1 — essentially impossible
    assert(!consensus::CheckProofOfWork(hard));
}
