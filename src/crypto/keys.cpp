// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "keys.h"

#include <cstring>
#include <stdexcept>

#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <cstdio>
#endif

extern "C" {
#include "ed25519.h"
}

namespace flow {

// ---------------------------------------------------------------------------
// Platform-specific secure random bytes
// ---------------------------------------------------------------------------

static void secure_random(void* buf, size_t len) {
#if defined(__linux__)
    ssize_t ret = getrandom(buf, len, 0);
    if (ret < 0 || static_cast<size_t>(ret) != len) {
        throw std::runtime_error("getrandom failed");
    }
#elif defined(__APPLE__)
    if (SecRandomCopyBytes(kSecRandomDefault, len, static_cast<uint8_t*>(buf)) != errSecSuccess) {
        throw std::runtime_error("SecRandomCopyBytes failed");
    }
#elif defined(_WIN32)
    if (BCryptGenRandom(NULL, static_cast<PUCHAR>(buf), static_cast<ULONG>(len),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
#else
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        throw std::runtime_error("cannot open /dev/urandom");
    }
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    if (n != len) {
        throw std::runtime_error("short read from /dev/urandom");
    }
#endif
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

KeyPair generate_keypair() {
    KeyPair kp;

    // Generate 32 bytes of cryptographically secure random data as the seed
    secure_random(kp.privkey.data(), 32);

    // Derive the public key from the seed using ed25519-donna
    ed25519_publickey(kp.privkey.data(), kp.pubkey.data());

    return kp;
}

std::array<uint8_t, 32> derive_pubkey(const uint8_t* privkey_seed) {
    std::array<uint8_t, 32> pubkey;
    ed25519_publickey(privkey_seed, pubkey.data());
    return pubkey;
}

} // namespace flow
