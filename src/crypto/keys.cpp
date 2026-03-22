// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "keys.h"
#include <sys/random.h>

extern "C" {
#include <ed25519.h>
}

namespace flow::crypto {

PrivKey generate_privkey() {
    PrivKey key;
    // Use Linux getrandom() — blocks until entropy is available
    ssize_t ret = getrandom(key.bytes(), 32, 0);
    if (ret != 32) {
        // getrandom should always succeed for 32 bytes after boot
        __builtin_trap();
    }
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
