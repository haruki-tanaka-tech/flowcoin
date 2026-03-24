/*
	Custom hash implementation for ed25519-donna.
	Routes internal Ed25519 hashing to Keccak-512 (pad byte 0x01).

	This makes FlowCoin's Ed25519 signatures incompatible with standard
	Ed25519 (which uses SHA-512). This is intentional.
*/

#ifndef ED25519_HASH_CUSTOM_H
#define ED25519_HASH_CUSTOM_H

#include "../hash/KeccakHash.h"
#include <stdint.h>
#include <stddef.h>

typedef Keccak_HashInstance ed25519_hash_context;

static inline void ed25519_hash_init(ed25519_hash_context *ctx) {
    /* Keccak-512: rate=576, capacity=1024, output=512 bits, pad=0x01 (original Keccak) */
    Keccak_HashInitialize(ctx, 576, 1024, 512, 0x01);
}

static inline void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen) {
    Keccak_HashUpdate(ctx, in, inlen * 8);  /* XKCP takes bit length */
}

static inline void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) {
    Keccak_HashFinal(ctx, hash);
}

static inline void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
    Keccak_HashInstance ctx;
    Keccak_HashInitialize(&ctx, 576, 1024, 512, 0x01);
    Keccak_HashUpdate(&ctx, in, inlen * 8);
    Keccak_HashFinal(&ctx, hash);
}

#endif /* ED25519_HASH_CUSTOM_H */
