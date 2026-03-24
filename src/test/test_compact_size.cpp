// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for CompactSize (Bitcoin-style variable-length integer) encoding
// and decoding via DataWriter / DataReader.

#include "util/serialize.h"
#include <cassert>
#include <cstdint>
#include <vector>

// Helper: encode a value and return the encoded bytes
static std::vector<uint8_t> encode_compact(uint64_t v) {
    flow::DataWriter w;
    w.write_compact_size(v);
    return w.data();
}

// Helper: decode a compact size from bytes
static uint64_t decode_compact(const std::vector<uint8_t>& data) {
    flow::DataReader r(data.data(), data.size());
    uint64_t v = r.read_compact_size();
    assert(!r.error());
    return v;
}

// Helper: return the encoded size of a compact size value
static size_t encoded_size(uint64_t v) {
    return encode_compact(v).size();
}

void test_compact_size() {
    // -----------------------------------------------------------------------
    // Test 1: Encode/decode 0 — single byte
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(0);
        assert(data.size() == 1);
        assert(data[0] == 0x00);
        assert(decode_compact(data) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 2: Encode/decode 1 — single byte
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(1);
        assert(data.size() == 1);
        assert(data[0] == 0x01);
        assert(decode_compact(data) == 1);
    }

    // -----------------------------------------------------------------------
    // Test 3: Encode/decode 252 — maximum single-byte value
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(252);
        assert(data.size() == 1);
        assert(data[0] == 0xfc);
        assert(decode_compact(data) == 252);
    }

    // -----------------------------------------------------------------------
    // Test 4: Encode/decode 253 — triggers 3-byte encoding (0xFD prefix)
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(253);
        assert(data.size() == 3);
        assert(data[0] == 0xfd);
        assert(decode_compact(data) == 253);
    }

    // -----------------------------------------------------------------------
    // Test 5: Encode/decode 254 — 3-byte encoding
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(254);
        assert(data.size() == 3);
        assert(data[0] == 0xfd);
        assert(decode_compact(data) == 254);
    }

    // -----------------------------------------------------------------------
    // Test 6: Encode/decode 0xFFFF — maximum 3-byte value
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(0xFFFF);
        assert(data.size() == 3);
        assert(data[0] == 0xfd);
        assert(decode_compact(data) == 0xFFFF);
    }

    // -----------------------------------------------------------------------
    // Test 7: Encode/decode 0x10000 — triggers 5-byte encoding (0xFE prefix)
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(0x10000);
        assert(data.size() == 5);
        assert(data[0] == 0xfe);
        assert(decode_compact(data) == 0x10000);
    }

    // -----------------------------------------------------------------------
    // Test 8: Encode/decode 0xFFFFFFFF — maximum 5-byte value
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(0xFFFFFFFF);
        assert(data.size() == 5);
        assert(data[0] == 0xfe);
        assert(decode_compact(data) == 0xFFFFFFFF);
    }

    // -----------------------------------------------------------------------
    // Test 9: Encode/decode 0x100000000 — triggers 9-byte encoding (0xFF prefix)
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(0x100000000ULL);
        assert(data.size() == 9);
        assert(data[0] == 0xff);
        assert(decode_compact(data) == 0x100000000ULL);
    }

    // -----------------------------------------------------------------------
    // Test 10: Encode/decode UINT64_MAX — maximum 9-byte value
    // -----------------------------------------------------------------------
    {
        uint64_t max_val = 0xFFFFFFFFFFFFFFFFULL;
        auto data = encode_compact(max_val);
        assert(data.size() == 9);
        assert(data[0] == 0xff);
        assert(decode_compact(data) == max_val);
    }

    // -----------------------------------------------------------------------
    // Test 11: Round-trip for all boundary values
    // -----------------------------------------------------------------------
    {
        uint64_t boundary_values[] = {
            0, 1, 127, 128, 251, 252,           // single-byte range
            253, 254, 255, 256, 1000,            // 3-byte range
            0xFFFE, 0xFFFF,                      // 3-byte boundary
            0x10000, 0x10001,                    // 5-byte range
            0xFFFFFFFE, 0xFFFFFFFF,              // 5-byte boundary
            0x100000000ULL, 0x100000001ULL,      // 9-byte range
            0xFFFFFFFFFFFFFFFEULL,               // near max
            0xFFFFFFFFFFFFFFFFULL,               // max
        };

        for (uint64_t val : boundary_values) {
            auto encoded = encode_compact(val);
            assert(!encoded.empty());

            flow::DataReader r(encoded.data(), encoded.size());
            uint64_t decoded = r.read_compact_size();
            assert(!r.error());
            assert(decoded == val);
            assert(r.eof());
        }
    }

    // -----------------------------------------------------------------------
    // Test 12: encoded_size() matches actual encode length for all ranges
    // -----------------------------------------------------------------------
    {
        // 1-byte range
        assert(encoded_size(0) == 1);
        assert(encoded_size(100) == 1);
        assert(encoded_size(252) == 1);

        // 3-byte range
        assert(encoded_size(253) == 3);
        assert(encoded_size(0xFFFF) == 3);

        // 5-byte range
        assert(encoded_size(0x10000) == 5);
        assert(encoded_size(0xFFFFFFFF) == 5);

        // 9-byte range
        assert(encoded_size(0x100000000ULL) == 9);
        assert(encoded_size(0xFFFFFFFFFFFFFFFFULL) == 9);
    }

    // -----------------------------------------------------------------------
    // Test 13: Multiple compact sizes in sequence
    // -----------------------------------------------------------------------
    {
        flow::DataWriter w;
        w.write_compact_size(0);
        w.write_compact_size(252);
        w.write_compact_size(253);
        w.write_compact_size(0xFFFF);
        w.write_compact_size(0x10000);
        w.write_compact_size(0xFFFFFFFF);
        w.write_compact_size(0x100000000ULL);

        // Total: 1 + 1 + 3 + 3 + 5 + 5 + 9 = 27 bytes
        assert(w.size() == 27);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_compact_size() == 0);
        assert(r.read_compact_size() == 252);
        assert(r.read_compact_size() == 253);
        assert(r.read_compact_size() == 0xFFFF);
        assert(r.read_compact_size() == 0x10000);
        assert(r.read_compact_size() == 0xFFFFFFFF);
        assert(r.read_compact_size() == 0x100000000ULL);
        assert(!r.error());
        assert(r.eof());
    }

    // -----------------------------------------------------------------------
    // Test 14: VarInt-style encode/decode with DataWriter/DataReader
    // (using u8/u16/u32/u64 directly as a VarInt alternative)
    // -----------------------------------------------------------------------
    {
        // Verify that writing raw integers and reading them back works
        // for the same sequence of types
        flow::DataWriter w;
        w.write_u8(42);
        w.write_u16_le(1000);
        w.write_u32_le(70000);
        w.write_u64_le(0xDEADBEEFCAFEULL);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_u8() == 42);
        assert(r.read_u16_le() == 1000);
        assert(r.read_u32_le() == 70000);
        assert(r.read_u64_le() == 0xDEADBEEFCAFEULL);
        assert(!r.error());
        assert(r.eof());
    }

    // -----------------------------------------------------------------------
    // Test 15: Reading from truncated data sets error flag
    // -----------------------------------------------------------------------
    {
        // Truncated 3-byte encoding: only 2 bytes instead of 3
        uint8_t truncated[] = {0xfd, 0x01};
        flow::DataReader r(truncated, 2);
        uint64_t val = r.read_compact_size();
        assert(r.error());
        (void)val;
    }

    // -----------------------------------------------------------------------
    // Test 16: Reading from empty data sets error flag
    // -----------------------------------------------------------------------
    {
        flow::DataReader r(nullptr, 0);
        uint64_t val = r.read_compact_size();
        assert(r.error());
        (void)val;
    }

    // -----------------------------------------------------------------------
    // Test 17: Little-endian byte order verification for 3-byte encoding
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(0x0102);  // 258
        assert(data.size() == 3);
        assert(data[0] == 0xfd);
        assert(data[1] == 0x02);  // low byte
        assert(data[2] == 0x01);  // high byte
    }

    // -----------------------------------------------------------------------
    // Test 18: Little-endian byte order verification for 5-byte encoding
    // -----------------------------------------------------------------------
    {
        auto data = encode_compact(0x01020304);
        assert(data.size() == 5);
        assert(data[0] == 0xfe);
        assert(data[1] == 0x04);  // lowest byte
        assert(data[2] == 0x03);
        assert(data[3] == 0x02);
        assert(data[4] == 0x01);  // highest byte
    }

    // -----------------------------------------------------------------------
    // Test 19: DataWriter write_bytes round-trip
    // -----------------------------------------------------------------------
    {
        flow::DataWriter w;
        uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
        w.write_bytes(data, 4);

        flow::DataReader r(w.data().data(), w.size());
        auto read_back = r.read_bytes(4);
        assert(!r.error());
        assert(read_back.size() == 4);
        assert(read_back[0] == 0xDE);
        assert(read_back[1] == 0xAD);
        assert(read_back[2] == 0xBE);
        assert(read_back[3] == 0xEF);
    }

    // -----------------------------------------------------------------------
    // Test 20: DataWriter size tracking
    // -----------------------------------------------------------------------
    {
        flow::DataWriter w;
        assert(w.size() == 0);

        w.write_u8(42);
        assert(w.size() == 1);

        w.write_u16_le(0x1234);
        assert(w.size() == 3);

        w.write_u32_le(0);
        assert(w.size() == 7);

        w.write_u64_le(0);
        assert(w.size() == 15);
    }

    // -----------------------------------------------------------------------
    // Test 21: DataWriter with reserve
    // -----------------------------------------------------------------------
    {
        flow::DataWriter w(1024);
        for (int i = 0; i < 100; i++) {
            w.write_u32_le(static_cast<uint32_t>(i));
        }
        assert(w.size() == 400);

        flow::DataReader r(w.data().data(), w.size());
        for (int i = 0; i < 100; i++) {
            assert(r.read_u32_le() == static_cast<uint32_t>(i));
        }
        assert(!r.error());
        assert(r.eof());
    }

    // -----------------------------------------------------------------------
    // Test 22: DataWriter release transfers ownership
    // -----------------------------------------------------------------------
    {
        flow::DataWriter w;
        w.write_u32_le(0x42424242);
        auto released = w.release();
        assert(released.size() == 4);
        assert(w.size() == 0);  // writer is empty after release
    }

    // -----------------------------------------------------------------------
    // Test 23: DataReader remaining() and eof()
    // -----------------------------------------------------------------------
    {
        uint8_t data[] = {1, 2, 3, 4, 5};
        flow::DataReader r(data, 5);

        assert(r.remaining() == 5);
        assert(!r.eof());

        r.read_u8();
        assert(r.remaining() == 4);

        r.read_u16_le();
        assert(r.remaining() == 2);

        r.read_u8();
        assert(r.remaining() == 1);

        r.read_u8();
        assert(r.remaining() == 0);
        assert(r.eof());
    }

    // -----------------------------------------------------------------------
    // Test 24: DataReader error_msg provides useful info
    // -----------------------------------------------------------------------
    {
        uint8_t data[] = {1, 2};
        flow::DataReader r(data, 2);
        r.read_u32_le();  // tries to read 4 bytes from 2-byte buffer
        assert(r.error());
        std::string msg = r.error_msg();
        assert(!msg.empty());
        assert(msg.find("DataReader") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 25: Float write/read round-trip with special values
    // -----------------------------------------------------------------------
    {
        flow::DataWriter w;
        w.write_float_le(0.0f);
        w.write_float_le(1.0f);
        w.write_float_le(-1.0f);
        w.write_float_le(3.14159f);
        w.write_float_le(1e-38f);
        w.write_float_le(1e+38f);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_float_le() == 0.0f);
        assert(r.read_float_le() == 1.0f);
        assert(r.read_float_le() == -1.0f);

        float pi = r.read_float_le();
        assert(pi > 3.14f && pi < 3.15f);

        float small = r.read_float_le();
        assert(small > 0.0f && small < 1e-37f);

        float big = r.read_float_le();
        assert(big > 1e+37f);

        assert(!r.error());
        assert(r.eof());
    }

    // -----------------------------------------------------------------------
    // Test 26: Compact size stress test — sequential values
    // -----------------------------------------------------------------------
    {
        flow::DataWriter w;
        for (uint64_t v = 0; v <= 300; v++) {
            w.write_compact_size(v);
        }

        flow::DataReader r(w.data().data(), w.size());
        for (uint64_t v = 0; v <= 300; v++) {
            uint64_t read_val = r.read_compact_size();
            assert(!r.error());
            assert(read_val == v);
        }
        assert(!r.error());
    }

    // -----------------------------------------------------------------------
    // Test 27: Mixed types in a single stream
    // -----------------------------------------------------------------------
    {
        flow::DataWriter w;
        w.write_u8(0xFF);
        w.write_compact_size(1000);
        w.write_u32_le(0xDEADBEEF);
        w.write_compact_size(0x100000000ULL);
        w.write_float_le(2.718f);
        w.write_i64_le(-12345678);
        w.write_compact_size(42);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_u8() == 0xFF);
        assert(r.read_compact_size() == 1000);
        assert(r.read_u32_le() == 0xDEADBEEF);
        assert(r.read_compact_size() == 0x100000000ULL);

        float e_val = r.read_float_le();
        assert(e_val > 2.71f && e_val < 2.72f);

        assert(r.read_i64_le() == -12345678);
        assert(r.read_compact_size() == 42);
        assert(!r.error());
        assert(r.eof());
    }

    // -----------------------------------------------------------------------
    // Test 28: Large sequence of compact sizes
    // -----------------------------------------------------------------------
    {
        flow::DataWriter w;
        constexpr int count = 10000;
        for (int i = 0; i < count; i++) {
            w.write_compact_size(static_cast<uint64_t>(i * i));
        }

        flow::DataReader r(w.data().data(), w.size());
        for (int i = 0; i < count; i++) {
            uint64_t val = r.read_compact_size();
            assert(!r.error());
            assert(val == static_cast<uint64_t>(i * i));
        }
        assert(r.eof());
    }
}
