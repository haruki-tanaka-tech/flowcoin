// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#pragma once

#include "core/types.h"

namespace flow::crypto {

// Generate a new random Ed25519 private key using system CSPRNG
PrivKey generate_privkey();

// Derive the Ed25519 public key from a private key
PubKey derive_pubkey(const PrivKey& privkey);

// Generate a keypair (private key from CSPRNG, then derive public)
struct KeyPair {
    PrivKey privkey;
    PubKey pubkey;
};

KeyPair generate_keypair();

} // namespace flow::crypto
