// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "util/serialize.h"
#include <cassert>
#include <cstring>
#include <cmath>
#include <stdexcept>
#include <limits>

void test_serialize() {
    // --- DataWriter / DataReader round-trip: uint8 ---
    {
        flow::DataWriter w;
        w.write_u8(0);
        w.write_u8(127);
        w.write_u8(255);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_u8() == 0);
        assert(r.read_u8() == 127);
        assert(r.read_u8() == 255);
        assert(r.eof());
        assert(!r.error());
    }

    // --- uint16 ---
    {
        flow::DataWriter w;
        w.write_u16_le(0);
        w.write_u16_le(0x1234);
        w.write_u16_le(0xFFFF);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_u16_le() == 0);
        assert(r.read_u16_le() == 0x1234);
        assert(r.read_u16_le() == 0xFFFF);
        assert(r.eof());
        assert(!r.error());
    }

    // --- uint32 ---
    {
        flow::DataWriter w;
        w.write_u32_le(0);
        w.write_u32_le(0x12345678);
        w.write_u32_le(0xFFFFFFFF);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_u32_le() == 0);
        assert(r.read_u32_le() == 0x12345678);
        assert(r.read_u32_le() == 0xFFFFFFFF);
        assert(r.eof());
        assert(!r.error());
    }

    // --- uint64 ---
    {
        flow::DataWriter w;
        w.write_u64_le(0);
        w.write_u64_le(0x123456789ABCDEF0ULL);
        w.write_u64_le(0xFFFFFFFFFFFFFFFFULL);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_u64_le() == 0);
        assert(r.read_u64_le() == 0x123456789ABCDEF0ULL);
        assert(r.read_u64_le() == 0xFFFFFFFFFFFFFFFFULL);
        assert(r.eof());
        assert(!r.error());
    }

    // --- int64 ---
    {
        flow::DataWriter w;
        w.write_i64_le(0);
        w.write_i64_le(-1);
        w.write_i64_le(std::numeric_limits<int64_t>::min());
        w.write_i64_le(std::numeric_limits<int64_t>::max());

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_i64_le() == 0);
        assert(r.read_i64_le() == -1);
        assert(r.read_i64_le() == std::numeric_limits<int64_t>::min());
        assert(r.read_i64_le() == std::numeric_limits<int64_t>::max());
        assert(r.eof());
        assert(!r.error());
    }

    // --- float ---
    {
        flow::DataWriter w;
        w.write_float_le(0.0f);
        w.write_float_le(1.0f);
        w.write_float_le(-3.14f);
        w.write_float_le(5.5f);

        flow::DataReader r(w.data().data(), w.size());

        // Bit-exact comparison via memcpy
        auto check_float = [](float got, float expected) {
            uint32_t g, e;
            std::memcpy(&g, &got, 4);
            std::memcpy(&e, &expected, 4);
            assert(g == e);
        };

        check_float(r.read_float_le(), 0.0f);
        check_float(r.read_float_le(), 1.0f);
        check_float(r.read_float_le(), -3.14f);
        check_float(r.read_float_le(), 5.5f);
        assert(r.eof());
        assert(!r.error());
    }

    // --- raw bytes ---
    {
        uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        flow::DataWriter w;
        w.write_bytes(data, 5);

        flow::DataReader r(w.data().data(), w.size());
        auto read_back = r.read_bytes(5);
        assert(read_back.size() == 5);
        assert(std::memcmp(read_back.data(), data, 5) == 0);
        assert(r.eof());
        assert(!r.error());
    }

    // --- CompactSize: 1-byte encoding (< 0xfd) ---
    {
        flow::DataWriter w;
        w.write_compact_size(0);
        w.write_compact_size(1);
        w.write_compact_size(252);  // max 1-byte value

        assert(w.size() == 3);  // 1 + 1 + 1

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_compact_size() == 0);
        assert(r.read_compact_size() == 1);
        assert(r.read_compact_size() == 252);
        assert(r.eof());
        assert(!r.error());
    }

    // --- CompactSize: 2-byte encoding (0xfd prefix) ---
    {
        flow::DataWriter w;
        w.write_compact_size(253);     // min 2-byte value
        w.write_compact_size(0xFFFF);  // max 2-byte value

        // 0xfd prefix (1 byte) + 2 bytes = 3 bytes each
        assert(w.size() == 6);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_compact_size() == 253);
        assert(r.read_compact_size() == 0xFFFF);
        assert(r.eof());
        assert(!r.error());
    }

    // --- CompactSize: 4-byte encoding (0xfe prefix) ---
    {
        flow::DataWriter w;
        w.write_compact_size(0x10000);     // min 4-byte value
        w.write_compact_size(0xFFFFFFFF);  // max 4-byte value

        // 0xfe prefix (1 byte) + 4 bytes = 5 bytes each
        assert(w.size() == 10);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_compact_size() == 0x10000);
        assert(r.read_compact_size() == 0xFFFFFFFF);
        assert(r.eof());
        assert(!r.error());
    }

    // --- CompactSize: 8-byte encoding (0xff prefix) ---
    {
        flow::DataWriter w;
        w.write_compact_size(0x100000000ULL);    // min 8-byte value
        w.write_compact_size(0xFFFFFFFFFFFFFFFFULL);  // max

        // 0xff prefix (1 byte) + 8 bytes = 9 bytes each
        assert(w.size() == 18);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_compact_size() == 0x100000000ULL);
        assert(r.read_compact_size() == 0xFFFFFFFFFFFFFFFFULL);
        assert(r.eof());
        assert(!r.error());
    }

    // --- DataReader: error on reading past end ---
    {
        uint8_t data[] = {0x01, 0x02};
        flow::DataReader r(data, 2);
        assert(!r.error());
        assert(r.remaining() == 2);

        r.read_u8();
        assert(r.remaining() == 1);
        assert(!r.error());

        // Try to read 4 bytes when only 1 remains
        r.read_u32_le();
        assert(r.error());
    }

    // --- DataReader: remaining() and eof() ---
    {
        uint8_t data[8] = {};
        flow::DataReader r(data, 8);
        assert(r.remaining() == 8);
        assert(!r.eof());

        r.read_u32_le();
        assert(r.remaining() == 4);
        assert(!r.eof());

        r.read_u32_le();
        assert(r.remaining() == 0);
        assert(r.eof());
    }

    // --- DataWriter: reserve and release ---
    {
        flow::DataWriter w(1024);
        w.write_u32_le(42);
        assert(w.size() == 4);

        auto buf = w.release();
        assert(buf.size() == 4);
        // After release, writer should be empty
        assert(w.size() == 0);
    }

    // --- Mixed types in sequence ---
    {
        flow::DataWriter w;
        w.write_u8(0xAA);
        w.write_u16_le(0xBBCC);
        w.write_u32_le(0xDDEEFF00);
        w.write_u64_le(0x1122334455667788ULL);
        w.write_i64_le(-42);
        w.write_float_le(2.718f);
        w.write_compact_size(300);

        flow::DataReader r(w.data().data(), w.size());
        assert(r.read_u8() == 0xAA);
        assert(r.read_u16_le() == 0xBBCC);
        assert(r.read_u32_le() == 0xDDEEFF00);
        assert(r.read_u64_le() == 0x1122334455667788ULL);
        assert(r.read_i64_le() == -42);

        float f = r.read_float_le();
        uint32_t fbits, ebits;
        float ef = 2.718f;
        std::memcpy(&fbits, &f, 4);
        std::memcpy(&ebits, &ef, 4);
        assert(fbits == ebits);

        assert(r.read_compact_size() == 300);
        assert(r.eof());
        assert(!r.error());
    }

    // --- error_msg ---
    {
        uint8_t data[] = {0x01};
        flow::DataReader r(data, 1);
        assert(r.error_msg().empty());

        r.read_u32_le();  // need 4 bytes, only 1 available
        assert(r.error());
        assert(!r.error_msg().empty());
    }
}
