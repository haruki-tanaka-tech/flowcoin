// Custom random bytes for ed25519-donna using Linux getrandom()
#include <sys/random.h>
#include <stddef.h>

void ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len) {
    getrandom(p, len, 0);
}
