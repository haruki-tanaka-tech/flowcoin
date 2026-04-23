// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// keccak256d.cl -- OpenCL Keccak-256d mining kernel for FlowCoin.
//
// Implements the full Keccak-1600 permutation (24 rounds) with original
// Keccak padding (suffix byte 0x01, NOT SHA-3's 0x06).
//
// Mining kernel: each work item gets a unique nonce via get_global_id(0)
// plus a base offset, writes it into header[84..87], computes
// keccak256(keccak256(header_92)) and compares against target.

// =========================================================================
// Keccak-1600 round constants
// =========================================================================

__constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

// Rotation offsets for rho step
__constant int ROTC[24] = {
     1,  3,  6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44
};

// pi step index mapping
__constant int PILN[24] = {
    10,  7, 11, 17, 18,  3,
     5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2,
    20, 14, 22,  9,  6,  1
};

// =========================================================================
// Keccak-1600 permutation (24 rounds)
// =========================================================================

inline void keccak_f1600(ulong st[25])
{
    ulong bc[5];

    for (int round = 0; round < 24; ++round) {
        // Theta
        bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        ulong t;
        t = bc[4] ^ rotate(bc[1], (ulong)1);
        st[0]  ^= t; st[5]  ^= t; st[10] ^= t; st[15] ^= t; st[20] ^= t;
        t = bc[0] ^ rotate(bc[2], (ulong)1);
        st[1]  ^= t; st[6]  ^= t; st[11] ^= t; st[16] ^= t; st[21] ^= t;
        t = bc[1] ^ rotate(bc[3], (ulong)1);
        st[2]  ^= t; st[7]  ^= t; st[12] ^= t; st[17] ^= t; st[22] ^= t;
        t = bc[2] ^ rotate(bc[4], (ulong)1);
        st[3]  ^= t; st[8]  ^= t; st[13] ^= t; st[18] ^= t; st[23] ^= t;
        t = bc[3] ^ rotate(bc[0], (ulong)1);
        st[4]  ^= t; st[9]  ^= t; st[14] ^= t; st[19] ^= t; st[24] ^= t;

        // Rho + Pi
        ulong tmp = st[1];
        for (int j = 0; j < 24; ++j) {
            int idx = PILN[j];
            ulong sv = st[idx];
            st[idx] = rotate(tmp, (ulong)ROTC[j]);
            tmp = sv;
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            ulong c0 = st[j + 0];
            ulong c1 = st[j + 1];
            ulong c2 = st[j + 2];
            ulong c3 = st[j + 3];
            ulong c4 = st[j + 4];
            st[j + 0] = c0 ^ ((~c1) & c2);
            st[j + 1] = c1 ^ ((~c2) & c3);
            st[j + 2] = c2 ^ ((~c3) & c4);
            st[j + 3] = c3 ^ ((~c4) & c0);
            st[j + 4] = c4 ^ ((~c0) & c1);
        }

        // Iota
        st[0] ^= RC[round];
    }
}

// =========================================================================
// keccak256: hash arbitrary data (up to ~rate bytes in first block)
// For mining we only need two fixed sizes: 92 bytes and 32 bytes.
// =========================================================================

// Keccak-256 of exactly 92 bytes (header).
// rate = 136 bytes = 17 lanes.  92 < 136 so single absorb block.
// Padding: original Keccak suffix 0x01.
// Byte 92 gets XORed with 0x01 (domain), byte 135 gets XORed with 0x80 (final).
inline void keccak256_92(const uchar data[92], uchar out[32])
{
    ulong st[25];
    for (int i = 0; i < 25; ++i) st[i] = 0;

    // Absorb 92 bytes = 11 full lanes (88 bytes) + 4 remaining bytes
    // Load 11 full 8-byte lanes
    for (int i = 0; i < 11; ++i) {
        ulong lane = 0;
        for (int b = 0; b < 8; ++b)
            lane |= ((ulong)data[i * 8 + b]) << (b * 8);
        st[i] ^= lane;
    }

    // Lane 11: bytes 88..91 (4 data bytes) + padding byte 0x01 at position 92
    // data[88..91] are the 4 remaining bytes, byte 92 (= lane 11 byte 4) is 0x01
    {
        ulong lane = 0;
        for (int b = 0; b < 4; ++b)
            lane |= ((ulong)data[88 + b]) << (b * 8);
        lane |= ((ulong)0x01) << (4 * 8);  // padding suffix at byte offset 92
        st[11] ^= lane;
    }

    // Final padding bit: byte 135 = last byte of rate (lane 16, byte 7) gets 0x80
    st[16] ^= ((ulong)0x80) << (7 * 8);

    // Permute
    keccak_f1600(st);

    // Squeeze: output first 32 bytes (4 lanes)
    for (int i = 0; i < 4; ++i) {
        ulong lane = st[i];
        for (int b = 0; b < 8; ++b)
            out[i * 8 + b] = (uchar)(lane >> (b * 8));
    }
}

// Keccak-256 of exactly 32 bytes (for second pass of double hash).
// 32 < 136, so single absorb block.
// Byte 32 gets 0x01, byte 135 gets 0x80.
inline void keccak256_32(const uchar data[32], uchar out[32])
{
    ulong st[25];
    for (int i = 0; i < 25; ++i) st[i] = 0;

    // Absorb 32 bytes = 4 full lanes
    for (int i = 0; i < 4; ++i) {
        ulong lane = 0;
        for (int b = 0; b < 8; ++b)
            lane |= ((ulong)data[i * 8 + b]) << (b * 8);
        st[i] ^= lane;
    }

    // Padding: byte 32 = lane 4 byte 0 gets 0x01
    st[4] ^= (ulong)0x01;

    // Final padding bit: byte 135 = lane 16 byte 7 gets 0x80
    st[16] ^= ((ulong)0x80) << (7 * 8);

    // Permute
    keccak_f1600(st);

    // Squeeze 32 bytes
    for (int i = 0; i < 4; ++i) {
        ulong lane = st[i];
        for (int b = 0; b < 8; ++b)
            out[i * 8 + b] = (uchar)(lane >> (b * 8));
    }
}

// =========================================================================
// Mining kernel
// =========================================================================
//
// Args:
//   header      - 92-byte block header (nonce bytes [84..87] will be overwritten)
//   target      - 32-byte big-endian target
//   nonce_base  - starting nonce; each work item adds get_global_id(0)
//   result_nonce - output: winning nonce (uint)
//   result_hash  - output: 32-byte winning hash
//   result_found - output: set to 1 if a solution was found

__kernel void mine(
    __global const uchar* header,       // 92 bytes
    __global const uchar* target,       // 32 bytes, big-endian
    const uint nonce_base,
    __global uint*  result_nonce,
    __global uchar* result_hash,        // 32 bytes
    __global uint*  result_found
)
{
    // Early exit if another work item already found a solution
    if (*result_found != 0)
        return;

    uint gid = get_global_id(0);
    uint nonce = nonce_base + gid;

    // Copy header to private memory and patch nonce at [84..87] (little-endian)
    uchar hdr[92];
    for (int i = 0; i < 92; ++i)
        hdr[i] = header[i];

    hdr[84] = (uchar)(nonce);
    hdr[85] = (uchar)(nonce >> 8);
    hdr[86] = (uchar)(nonce >> 16);
    hdr[87] = (uchar)(nonce >> 24);

    // First hash
    uchar inner[32];
    keccak256_92(hdr, inner);

    // Second hash
    uchar hash[32];
    keccak256_32(inner, hash);

    // Load target into private memory
    uchar tgt[32];
    for (int i = 0; i < 32; ++i)
        tgt[i] = target[i];

    // Compare hash <= target (big-endian, lexicographic)
    bool valid = true;
    for (int i = 0; i < 32; ++i) {
        if (hash[i] < tgt[i]) break;       // hash < target: valid
        if (hash[i] > tgt[i]) {
            valid = false;
            break;
        }
        // equal: continue to next byte
    }

    if (valid) {
        // Atomic set to avoid races (first writer wins)
        if (atomic_cmpxchg(result_found, 0u, 1u) == 0u) {
            *result_nonce = nonce;
            for (int i = 0; i < 32; ++i)
                result_hash[i] = hash[i];
        }
    }
}
