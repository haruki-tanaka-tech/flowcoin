// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "keys.h"

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
#include <ed25519.h>
}

namespace flow::crypto {

static void secure_random(uint8_t* buf, size_t len) {
#if defined(__linux__)
    getrandom(buf, len, 0);
#elif defined(__APPLE__)
    SecRandomCopyBytes(kSecRandomDefault, len, buf);
#elif defined(_WIN32)
    BCryptGenRandom(NULL, buf, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) { fread(buf, 1, len, f); fclose(f); }
#endif
}

PrivKey generate_privkey() {
    PrivKey key;
    secure_random(key.bytes(), 32);
    return key;
}

PubKey derive_pubkey(const PrivKey& privkey) {
    PubKey pubkey;
    ed25519_publickey(privkey.bytes(), pubkey.bytes());
    return pubkey;
}

KeyPair generate_keypair() {
    KeyPair kp;
    kp.privkey = generate_privkey();
    kp.pubkey = derive_pubkey(kp.privkey);
    return kp;
}

} // namespace flow::crypto
