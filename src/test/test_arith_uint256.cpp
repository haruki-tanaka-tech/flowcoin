// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "util/arith_uint256.h"
#include "util/types.h"
#include <cassert>
#include <stdexcept>

void test_arith_uint256() {
    // SetCompact / GetCompact round-trip: Bitcoin genesis 0x1d00ffff
    {
        flow::arith_uint256 target;
        bool negative, overflow;
        target.SetCompact(0x1d00ffff, &negative, &overflow);
        assert(!negative);
        assert(!overflow);
        assert(target.GetCompact() == 0x1d00ffff);
        assert(!target.IsZero());
    }

    // FlowCoin initial: 0x1f00ffff
    {
        flow::arith_uint256 target;
        bool negative, overflow;
        target.SetCompact(0x1f00ffff, &negative, &overflow);
        assert(!negative);
        assert(!overflow);
        assert(target.GetCompact() == 0x1f00ffff);
        assert(!target.IsZero());
    }

    // Zero compact
    {
        flow::arith_uint256 target;
        bool neg, ovf;
        target.SetCompact(0, &neg, &ovf);
        assert(target.IsZero());
    }

    // Small value compact round-trip
    {
        flow::arith_uint256 target;
        bool neg, ovf;
        target.SetCompact(0x03123456, &neg, &ovf);
        assert(!neg && !ovf);
        assert(target.GetCompact() == 0x03123456);
    }

    // Arithmetic: multiplication 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
    {
        flow::arith_uint256 a(0xFFFFFFFFULL);
        flow::arith_uint256 b(0xFFFFFFFFULL);
        flow::arith_uint256 c = a * b;
        assert(c.GetLow64() == 0xFFFFFFFE00000001ULL);
    }

    // Arithmetic: multiply then divide by uint32 (used in difficulty adjustment)
    {
        flow::arith_uint256 target;
        target.SetCompact(0x1d00ffff);
        target *= 600;
        flow::arith_uint256 divisor(static_cast<uint64_t>(1209600));
        target /= divisor;
        assert(!target.IsZero());
    }

    // Comparison operators
    {
        flow::arith_uint256 a(100);
        flow::arith_uint256 b(200);
        assert(a < b);
        assert(b > a);
        assert(a != b);
        assert(a <= b);
        assert(b >= a);
        assert(a == flow::arith_uint256(100));

        // Equal values
        flow::arith_uint256 c(100);
        assert(a == c);
        assert(a <= c);
        assert(a >= c);
        assert(!(a < c));
        assert(!(a > c));
    }

    // UintToArith256 and ArithToUint256 round-trip
    {
        flow::uint256 hash;
        hash[0] = 0x42;
        hash[31] = 0xAB;
        auto arith = flow::UintToArith256(hash);
        auto back = flow::ArithToUint256(arith);
        assert(back == hash);
    }

    // Bit shifts
    {
        flow::arith_uint256 a(1);
        a <<= 255;
        assert(a.bits() == 256);
        a >>= 255;
        assert(a == flow::arith_uint256(1));
    }

    // Shift by 0 is identity
    {
        flow::arith_uint256 a(0x12345678ULL);
        flow::arith_uint256 b = a << 0;
        assert(a == b);
        b = a >> 0;
        assert(a == b);
    }

    // GetHex / SetHex round-trip
    {
        flow::arith_uint256 a;
        a.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
        assert(a == flow::arith_uint256(1));
        assert(a.GetHex() == "0000000000000000000000000000000000000000000000000000000000000001");
    }

    // GetLow64 with a larger value
    {
        flow::arith_uint256 a(0xDEADBEEFCAFE1234ULL);
        assert(a.GetLow64() == 0xDEADBEEFCAFE1234ULL);
    }

    // Addition
    {
        flow::arith_uint256 a(100);
        flow::arith_uint256 b(200);
        flow::arith_uint256 c = a + b;
        assert(c == flow::arith_uint256(300));
    }

    // Subtraction
    {
        flow::arith_uint256 a(300);
        flow::arith_uint256 b(100);
        flow::arith_uint256 c = a - b;
        assert(c == flow::arith_uint256(200));
    }

    // Increment/decrement
    {
        flow::arith_uint256 a(5);
        ++a;
        assert(a == flow::arith_uint256(6));
        --a;
        assert(a == flow::arith_uint256(5));
    }

    // Bitwise operations
    {
        flow::arith_uint256 a(0xFF00FF00ULL);
        flow::arith_uint256 b(0x0F0F0F0FULL);
        auto c = a & b;
        assert(c.GetLow64() == (0xFF00FF00ULL & 0x0F0F0F0FULL));
        auto d = a | b;
        assert(d.GetLow64() == (0xFF00FF00ULL | 0x0F0F0F0FULL));
        auto e = a ^ b;
        assert(e.GetLow64() == (0xFF00FF00ULL ^ 0x0F0F0F0FULL));
    }

    // IsNull / IsZero / IsNonZero
    {
        flow::arith_uint256 zero;
        assert(zero.IsNull());
        assert(zero.IsZero());
        assert(!zero.IsNonZero());

        flow::arith_uint256 one(1);
        assert(!one.IsNull());
        assert(!one.IsZero());
        assert(one.IsNonZero());
    }

    // bits()
    {
        flow::arith_uint256 zero;
        assert(zero.bits() == 0);

        flow::arith_uint256 one(1);
        assert(one.bits() == 1);

        flow::arith_uint256 two(2);
        assert(two.bits() == 2);

        flow::arith_uint256 big(0x80000000ULL);
        assert(big.bits() == 32);
    }
}
