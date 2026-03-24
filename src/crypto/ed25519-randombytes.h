/*
	Choose the random bytes implementation for ed25519-donna.
	We always use the custom platform-specific implementation.
*/

#define ED25519_CUSTOMRANDOM
#include "ed25519-randombytes-custom.h"
