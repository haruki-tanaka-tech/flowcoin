// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "primitives/block.h"
#include "hash/keccak.h"
#include <cassert>
#include <cstring>
#include <stdexcept>

void test_block_header() {
    // Default header: get_unsigned_data should be BLOCK_HEADER_UNSIGNED_SIZE bytes
    flow::CBlockHeader hdr;

    auto unsigned_data = hdr.get_unsigned_data();
    assert(unsigned_data.size() == flow::BLOCK_HEADER_UNSIGNED_SIZE);

    // Default values
    assert(hdr.height == 0);
    assert(hdr.timestamp == 0);
    assert(hdr.nbits == 0);
    assert(hdr.version == 1);

    // Set fields and verify they affect the unsigned data
    hdr.height = 12345;
    hdr.timestamp = 1742515200;
    hdr.nbits = 0x1f00ffff;

    auto data2 = hdr.get_unsigned_data();
    assert(data2.size() == flow::BLOCK_HEADER_UNSIGNED_SIZE);
    // The data should differ from default header
    assert(unsigned_data != data2);

    // Block hash should be deterministic
    auto hash1 = hdr.get_hash();
    auto hash2 = hdr.get_hash();
    assert(hash1 == hash2);
    assert(!hash1.is_null());

    // Block hash should be keccak256d of unsigned data
    auto expected_hash = flow::keccak256d(data2.data(), data2.size());
    assert(hash1 == expected_hash);

    // Different header fields produce different hash
    flow::CBlockHeader hdr2;
    hdr2.height = 1;
    assert(hdr.get_hash() != hdr2.get_hash());

    // CBlock inherits from CBlockHeader
    flow::CBlock block(hdr);
    assert(block.height == hdr.height);
    assert(block.timestamp == hdr.timestamp);
    assert(block.get_hash() == hdr.get_hash());
    assert(block.vtx.empty());
}
