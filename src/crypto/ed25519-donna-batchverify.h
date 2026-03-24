/*
	Public domain by Andrew M. <liquidsun@gmail.com>
	Ed25519 batch verification
*/

/*
	Batch verification of ed25519 signatures.
	This is a simple serial implementation that verifies each
	signature individually. A more optimized version could use
	multi-scalar multiplication, but correctness is more important.
*/

#define max_batch_size 64
#define heap_batch_size ((max_batch_size * 2) + 1)

/* verification context for batch operations */
typedef struct batch_heap_t {
	unsigned char r[heap_batch_size][16]; /* 128 bit random values */
	ge25519 points[heap_batch_size];
	bignum256modm scalars[heap_batch_size];
	size_t size;
} batch_heap;

/* simple serial batch verification: verify each signature independently */
int
ED25519_FN(ed25519_sign_open_batch) (const unsigned char **m, size_t *mlen, const unsigned char **pk, const unsigned char **RS, size_t num, int *valid) {
	size_t i;
	int ret = 0;

	for (i = 0; i < num; i++) {
		valid[i] = (ED25519_FN(ed25519_sign_open)(m[i], mlen[i], pk[i], RS[i]) == 0) ? 1 : 0;
		if (!valid[i])
			ret = 1;
	}

	/* 0 = all valid, non-zero = at least one invalid */
	return ret;
}
