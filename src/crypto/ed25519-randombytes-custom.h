// Cross-platform random bytes for ed25519-donna
#include <stddef.h>

#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#endif

void ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len) {
#if defined(__linux__)
    getrandom(p, len, 0);
#elif defined(__APPLE__)
    SecRandomCopyBytes(kSecRandomDefault, len, (uint8_t*)p);
#elif defined(_WIN32)
    BCryptGenRandom(NULL, (PUCHAR)p, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    // Fallback: /dev/urandom
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) { fread(p, 1, len, f); fclose(f); }
#endif
}
