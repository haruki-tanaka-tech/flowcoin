/*
	Choose the hash implementation for ed25519-donna.
	We always use the custom Keccak-512 hash.
*/

#define ED25519_CUSTOMHASH
#include "ed25519-hash-custom.h"
