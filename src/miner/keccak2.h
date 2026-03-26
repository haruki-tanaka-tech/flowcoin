#ifndef KECCAK2_H
#define KECCAK2_H

#include <stdint.h>
#include <stddef.h>

/* Keccak-256 (pad=0x01, NOT SHA-3)
 * Matches Ethereum's keccak256 */
void keccak256(const unsigned char *message, unsigned int len, unsigned char *digest);

/* Keccak-256d (double Keccak-256) */
void keccak256d(const unsigned char *message, unsigned int len, unsigned char *digest);

/* Incremental API (matching sha256_ctx pattern from sha2.h) */
typedef struct {
    /* Wraps XKCP Keccak_HashInstance internally */
    unsigned char opaque[512];
} keccak256_ctx;

void keccak256_init(keccak256_ctx *ctx);
void keccak256_update(keccak256_ctx *ctx, const unsigned char *message, unsigned int len);
void keccak256_final(keccak256_ctx *ctx, unsigned char *digest);

#endif
