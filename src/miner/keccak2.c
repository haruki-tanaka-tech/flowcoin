/*
 * Keccak-256 / Keccak-256d wrapper for cgminer.
 * Uses XKCP (eXtended Keccak Code Package) high-level API.
 * Pad byte 0x01 (original Keccak), NOT 0x06 (SHA-3).
 */

#include "keccak2.h"
#include "KeccakHash.h"
#include <string.h>
#include <assert.h>

/* One-shot Keccak-256 */
void keccak256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    Keccak_HashInstance hi;
    Keccak_HashInitialize_Keccak256(&hi);
    Keccak_HashUpdate(&hi, message, (size_t)len * 8);  /* API takes bits */
    Keccak_HashFinal(&hi, digest);
}

/* Double Keccak-256 (Keccak-256d) */
void keccak256d(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    unsigned char first[32];
    keccak256(message, len, first);
    keccak256(first, 32, digest);
}

/* Incremental API wrapping XKCP Keccak_HashInstance */

/* Compile-time check that our opaque buffer is large enough */
typedef char keccak2_size_check[sizeof(keccak256_ctx) >= sizeof(Keccak_HashInstance) ? 1 : -1];

void keccak256_init(keccak256_ctx *ctx)
{
    Keccak_HashInstance *hi = (Keccak_HashInstance *)ctx->opaque;
    Keccak_HashInitialize_Keccak256(hi);
}

void keccak256_update(keccak256_ctx *ctx, const unsigned char *message, unsigned int len)
{
    Keccak_HashInstance *hi = (Keccak_HashInstance *)ctx->opaque;
    Keccak_HashUpdate(hi, message, (size_t)len * 8);  /* API takes bits */
}

void keccak256_final(keccak256_ctx *ctx, unsigned char *digest)
{
    Keccak_HashInstance *hi = (Keccak_HashInstance *)ctx->opaque;
    Keccak_HashFinal(hi, digest);
}
