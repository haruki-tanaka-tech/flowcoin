// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for hex encoding/decoding utilities.

#include "util/strencodings.h"
#include "util/random.h"
#include "util/types.h"

#include <cassert>
#include <cstring>
#include <string>
#include <vector>

using namespace flow;

void test_strencodings() {

    // -----------------------------------------------------------------------
    // Test 1: hex_encode basic
    // -----------------------------------------------------------------------
    {
        uint8_t data[] = {0x00, 0x01, 0xff, 0xab, 0xcd};
        std::string hex = hex_encode(data, 5);
        assert(hex == "0001ffabcd");
    }

    // -----------------------------------------------------------------------
    // Test 2: hex_encode empty
    // -----------------------------------------------------------------------
    {
        std::string hex = hex_encode(nullptr, 0);
        assert(hex.empty());
    }

    // -----------------------------------------------------------------------
    // Test 3: hex_decode basic
    // -----------------------------------------------------------------------
    {
        auto bytes = hex_decode("0001ffabcd");
        assert(bytes.size() == 5);
        assert(bytes[0] == 0x00);
        assert(bytes[1] == 0x01);
        assert(bytes[2] == 0xff);
        assert(bytes[3] == 0xab);
        assert(bytes[4] == 0xcd);
    }

    // -----------------------------------------------------------------------
    // Test 4: hex_decode empty string
    // -----------------------------------------------------------------------
    {
        auto bytes = hex_decode("");
        assert(bytes.empty());
    }

    // -----------------------------------------------------------------------
    // Test 5: hex_decode invalid (odd length)
    // -----------------------------------------------------------------------
    {
        auto bytes = hex_decode("abc");
        assert(bytes.empty());
    }

    // -----------------------------------------------------------------------
    // Test 6: hex_decode invalid characters
    // -----------------------------------------------------------------------
    {
        auto bytes = hex_decode("gg");
        assert(bytes.empty());
    }

    // -----------------------------------------------------------------------
    // Test 7: hex_encode/decode round-trip
    // -----------------------------------------------------------------------
    {
        uint8_t data[32];
        GetRandBytes(data, 32);

        std::string hex = hex_encode(data, 32);
        assert(hex.size() == 64);

        auto decoded = hex_decode(hex);
        assert(decoded.size() == 32);
        assert(std::memcmp(decoded.data(), data, 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 8: hex_encode vector overload
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> data = {0xde, 0xad, 0xbe, 0xef};
        std::string hex = hex_encode(data);
        assert(hex == "deadbeef");
    }

    // -----------------------------------------------------------------------
    // Test 9: hex_decode uppercase
    // -----------------------------------------------------------------------
    {
        auto bytes = hex_decode("DEADBEEF");
        assert(bytes.size() == 4);
        assert(bytes[0] == 0xde);
        assert(bytes[1] == 0xad);
        assert(bytes[2] == 0xbe);
        assert(bytes[3] == 0xef);
    }

    // -----------------------------------------------------------------------
    // Test 10: hex_decode mixed case
    // -----------------------------------------------------------------------
    {
        auto bytes = hex_decode("DeAdBeEf");
        assert(bytes.size() == 4);
    }

    // -----------------------------------------------------------------------
    // Test 11: Large data round-trip
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> data(1024);
        GetRandBytes(data.data(), data.size());

        std::string hex = hex_encode(data);
        assert(hex.size() == 2048);

        auto decoded = hex_decode(hex);
        assert(decoded == data);
    }

    // -----------------------------------------------------------------------
    // Test 12: All byte values
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> all_bytes(256);
        for (int i = 0; i < 256; ++i) {
            all_bytes[i] = static_cast<uint8_t>(i);
        }

        std::string hex = hex_encode(all_bytes);
        assert(hex.size() == 512);

        auto decoded = hex_decode(hex);
        assert(decoded == all_bytes);
    }

    // -----------------------------------------------------------------------
    // Test 13: hex_encode single byte
    // -----------------------------------------------------------------------
    {
        uint8_t b = 0x42;
        assert(hex_encode(&b, 1) == "42");

        b = 0x00;
        assert(hex_encode(&b, 1) == "00");

        b = 0xff;
        assert(hex_encode(&b, 1) == "ff");
    }

    // -----------------------------------------------------------------------
    // Test 14: hex_decode single byte
    // -----------------------------------------------------------------------
    {
        auto bytes = hex_decode("42");
        assert(bytes.size() == 1);
        assert(bytes[0] == 0x42);
    }

    // -----------------------------------------------------------------------
    // Test 15: hex_encode_reverse
    // -----------------------------------------------------------------------
    {
        uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
        std::string rev = hex_encode_reverse<4>(data);
        assert(rev == "04030201");
    }

    // -----------------------------------------------------------------------
    // Test 16: hex_encode_reverse single byte
    // -----------------------------------------------------------------------
    {
        uint8_t data[1] = {0xAB};
        std::string rev = hex_encode_reverse<1>(data);
        assert(rev == "ab");
    }

    // -----------------------------------------------------------------------
    // Test 17: hex_encode produces lowercase
    // -----------------------------------------------------------------------
    {
        uint8_t data[] = {0xAB, 0xCD, 0xEF};
        std::string hex = hex_encode(data, 3);
        assert(hex == "abcdef");
    }

    // -----------------------------------------------------------------------
    // Test 18: hex_decode with leading zeros
    // -----------------------------------------------------------------------
    {
        auto bytes = hex_decode("0000000000");
        assert(bytes.size() == 5);
        for (auto b : bytes) assert(b == 0);
    }

    // -----------------------------------------------------------------------
    // Test 19: Uint256 round-trip via hex
    // -----------------------------------------------------------------------
    {
        uint256 hash = GetRandUint256();
        std::string hex = hex_encode(hash.data(), 32);
        auto decoded = hex_decode(hex);
        assert(decoded.size() == 32);
        assert(std::memcmp(decoded.data(), hash.data(), 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 20: Multiple round-trips are stable
    // -----------------------------------------------------------------------
    {
        uint8_t data[64];
        GetRandBytes(data, 64);

        std::string hex1 = hex_encode(data, 64);
        auto dec1 = hex_decode(hex1);
        std::string hex2 = hex_encode(dec1);
        auto dec2 = hex_decode(hex2);

        assert(hex1 == hex2);
        assert(dec1 == dec2);
    }
}
