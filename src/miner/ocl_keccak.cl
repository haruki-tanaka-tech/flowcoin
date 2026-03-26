/*
 * FlowCoin Keccak-256d OpenCL Mining Kernel
 * Works on: NVIDIA, AMD, Intel, Apple GPUs
 * No precompute — full hash every thread for correctness.
 */

__constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
    0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
    0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
    0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
    0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

__constant int PILN[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

__constant int ROTC[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

void keccak_f1600(ulong state[25]) {
    ulong C[5], D[5], temp;

    for (int round = 0; round < 24; round++) {
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x+4)%5] ^ ((C[(x+1)%5] << 1) | (C[(x+1)%5] >> 63));
            for (int y = 0; y < 25; y += 5)
                state[y+x] ^= D[x];
        }
        temp = state[1];
        for (int i = 0; i < 24; i++) {
            int j = PILN[i];
            ulong t = state[j];
            state[j] = (temp << ROTC[i]) | (temp >> (64 - ROTC[i]));
            temp = t;
        }
        for (int y = 0; y < 25; y += 5) {
            ulong t0=state[y], t1=state[y+1], t2=state[y+2], t3=state[y+3], t4=state[y+4];
            state[y]   = t0 ^ ((~t1) & t2);
            state[y+1] = t1 ^ ((~t2) & t3);
            state[y+2] = t2 ^ ((~t3) & t4);
            state[y+3] = t3 ^ ((~t4) & t0);
            state[y+4] = t4 ^ ((~t0) & t1);
        }
        state[0] ^= RC[round];
    }
}

/* Keccak-256: hash arbitrary data, output 32 bytes */
void keccak256(const uchar *data, int len, uchar *hash) {
    ulong state[25];
    for (int i = 0; i < 25; i++) state[i] = 0;

    int rate = 136;
    int offset = 0;

    /* Absorb full blocks */
    while (offset + rate <= len) {
        for (int i = 0; i < 17; i++) {
            ulong w = 0;
            for (int b = 0; b < 8; b++)
                w |= ((ulong)data[offset + i*8 + b]) << (b*8);
            state[i] ^= w;
        }
        keccak_f1600(state);
        offset += rate;
    }

    /* Final block with padding */
    uchar block[136];
    for (int i = 0; i < 136; i++) block[i] = 0;
    int remaining = len - offset;
    for (int i = 0; i < remaining; i++)
        block[i] = data[offset + i];
    block[remaining] = 0x01;
    block[135] |= 0x80;

    for (int i = 0; i < 17; i++) {
        ulong w = 0;
        for (int b = 0; b < 8; b++)
            w |= ((ulong)block[i*8 + b]) << (b*8);
        state[i] ^= w;
    }
    keccak_f1600(state);

    /* Squeeze 32 bytes */
    for (int i = 0; i < 4; i++) {
        ulong w = state[i];
        for (int b = 0; b < 8; b++)
            hash[i*8 + b] = (uchar)(w >> (b*8));
    }
}

__kernel void mine_keccak256d(
    __global const uchar *header_base,  /* 92 bytes */
    __global const uchar *target,       /* 32 bytes */
    uint start_nonce,
    uint nonce_offset,                  /* byte offset of nonce in header (84) */
    __global uint *found_nonce,
    __global uint *found_count
) {
    uint gid = get_global_id(0);
    uint nonce = start_nonce + gid;

    /* Copy header to private memory */
    uchar header[92];
    for (int i = 0; i < 92; i++)
        header[i] = header_base[i];

    /* Write nonce (little-endian uint32) */
    header[nonce_offset]     = (uchar)(nonce);
    header[nonce_offset + 1] = (uchar)(nonce >> 8);
    header[nonce_offset + 2] = (uchar)(nonce >> 16);
    header[nonce_offset + 3] = (uchar)(nonce >> 24);

    /* First Keccak-256 */
    uchar hash1[32];
    keccak256(header, 92, hash1);

    /* Second Keccak-256 (double hash) */
    uchar hash2[32];
    keccak256(hash1, 32, hash2);

    /* Compare with target (big-endian) */
    bool meets = true;
    for (int i = 0; i < 32; i++) {
        if (hash2[i] < target[i]) break;
        if (hash2[i] > target[i]) { meets = false; break; }
    }

    if (meets) {
        uint idx = atomic_add(found_count, 1);
        if (idx == 0)
            *found_nonce = nonce;
    }
}
