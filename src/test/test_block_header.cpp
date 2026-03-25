// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "primitives/block.h"
#include "hash/keccak.h"
#include <cassert>
#include <cstring>
#include <stdexcept>

void test_block_header() {
    // Default header: get_unsigned_data should be exactly 244 bytes
    flow::CBlockHeader hdr;

    auto unsigned_data = hdr.get_unsigned_data();
    assert(unsigned_data.size() == 244);

    // Default values
    assert(hdr.height == 0);
    assert(hdr.timestamp == 0);
    assert(hdr.nbits == 0);
    assert(hdr.version == 1);

    // Set fields and verify they affect the unsigned data
    hdr.height = 12345;
    hdr.timestamp = 1742515200;
    hdr.nbits = 0x1f00ffff;
    hdr.val_loss = 5.5f;
    hdr.prev_val_loss = 6.0f;
    hdr.d_model = 512;
    hdr.n_layers = 8;
    hdr.d_ff = 1024;
    hdr.n_slots = 1024;
    hdr.n_heads = 8;
    hdr.gru_dim = 512;
    hdr.reserved_field = 0;

    auto data2 = hdr.get_unsigned_data();
    assert(data2.size() == 244);
    // The data should differ from default header
    assert(unsigned_data != data2);

    // Verify height is at bytes 128-135 (little-endian)
    uint64_t height_read = 0;
    for (int i = 0; i < 8; i++) {
        height_read |= static_cast<uint64_t>(data2[128 + i]) << (i * 8);
    }
    assert(height_read == 12345);

    // Verify timestamp is at bytes 136-143
    int64_t ts_read = 0;
    uint64_t ts_u;
    std::memcpy(&ts_u, &data2[136], 8);
    // Since it's little-endian and we're likely on LE, just use memcpy
    // But to be safe, read byte by byte:
    ts_u = 0;
    for (int i = 0; i < 8; i++) {
        ts_u |= static_cast<uint64_t>(data2[136 + i]) << (i * 8);
    }
    ts_read = static_cast<int64_t>(ts_u);
    assert(ts_read == 1742515200);

    // Verify nbits at bytes 144-147
    uint32_t nbits_read = static_cast<uint32_t>(data2[144])
                        | (static_cast<uint32_t>(data2[145]) << 8)
                        | (static_cast<uint32_t>(data2[146]) << 16)
                        | (static_cast<uint32_t>(data2[147]) << 24);
    assert(nbits_read == 0x1f00ffff);

    // Verify val_loss at bytes 148-151 (IEEE 754 float, little-endian)
    float vl_read;
    std::memcpy(&vl_read, &data2[148], 4);
    uint32_t vl_bits, expected_bits;
    float expected_f = 5.5f;
    std::memcpy(&vl_bits, &vl_read, 4);
    std::memcpy(&expected_bits, &expected_f, 4);
    assert(vl_bits == expected_bits);

    // Block hash should be deterministic
    auto hash1 = hdr.get_hash();
    auto hash2 = hdr.get_hash();
    assert(hash1 == hash2);
    assert(!hash1.is_null());

    // Block hash should be keccak256d of unsigned data
    auto expected_hash = flow::keccak256d(data2.data(), data2.size());
    assert(hash1 == expected_hash);

    // get_training_hash should return the same as get_hash
    auto th = hdr.get_training_hash();
    assert(th == hash1);

    // Different header fields produce different hash
    flow::CBlockHeader hdr2;
    hdr2.height = 1;
    assert(hdr.get_hash() != hdr2.get_hash());

    // Miner pubkey is in the unsigned data at bytes 212-243
    hdr.miner_pubkey.fill(0xAB);
    auto data3 = hdr.get_unsigned_data();
    for (int i = 0; i < 32; i++) {
        assert(data3[212 + i] == 0xAB);
    }

    // Miner signature is NOT in the unsigned data (244 bytes, no room for 64 more)
    assert(data3.size() == 244);

    // CBlock inherits from CBlockHeader
    flow::CBlock block(hdr);
    assert(block.height == hdr.height);
    assert(block.timestamp == hdr.timestamp);
    assert(block.get_hash() == hdr.get_hash());
    assert(block.vtx.empty());
    assert(block.delta_payload.empty());
}
