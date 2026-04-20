// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "crypto/keys.h"
#include "crypto/sign.h"
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <vector>

void test_ed25519() {
    // Generate keypair and sign/verify round-trip
    auto kp = flow::generate_keypair();

    const uint8_t msg[] = "Hello, FlowCoin!";
    auto sig = flow::ed25519_sign(msg, sizeof(msg) - 1,
                                   kp.privkey.data(), kp.pubkey.data());

    // Verify should succeed
    assert(flow::ed25519_verify(msg, sizeof(msg) - 1,
                                 kp.pubkey.data(), sig.data()));

    // Tampered message should fail
    uint8_t tampered[] = "Hello, FlowCoin?";
    assert(!flow::ed25519_verify(tampered, sizeof(tampered) - 1,
                                  kp.pubkey.data(), sig.data()));

    // Tampered signature should fail
    auto bad_sig = sig;
    bad_sig[0] ^= 0xFF;
    assert(!flow::ed25519_verify(msg, sizeof(msg) - 1,
                                  kp.pubkey.data(), bad_sig.data()));

    // Wrong pubkey should fail
    auto kp2 = flow::generate_keypair();
    assert(!flow::ed25519_verify(msg, sizeof(msg) - 1,
                                  kp2.pubkey.data(), sig.data()));

    // derive_pubkey should match generated pubkey
    auto derived = flow::derive_pubkey(kp.privkey.data());
    assert(derived == kp.pubkey);

    // Empty message signing and verification
    auto empty_sig = flow::ed25519_sign(nullptr, 0,
                                         kp.privkey.data(), kp.pubkey.data());
    assert(flow::ed25519_verify(nullptr, 0,
                                 kp.pubkey.data(), empty_sig.data()));

    // Different messages produce different signatures
    const uint8_t msg2[] = "Different message";
    auto sig2 = flow::ed25519_sign(msg2, sizeof(msg2) - 1,
                                    kp.privkey.data(), kp.pubkey.data());
    // Signatures should differ
    assert(sig != sig2);

    // Two keypairs should produce different keys
    assert(kp.privkey != kp2.privkey);
    assert(kp.pubkey != kp2.pubkey);

    // Signing same message with different keys produces different sigs
    auto sig_kp2 = flow::ed25519_sign(msg, sizeof(msg) - 1,
                                       kp2.privkey.data(), kp2.pubkey.data());
    assert(flow::ed25519_verify(msg, sizeof(msg) - 1,
                                 kp2.pubkey.data(), sig_kp2.data()));
    assert(sig != sig_kp2);

    // Large message
    std::vector<uint8_t> large_msg(10000, 0xAB);
    auto large_sig = flow::ed25519_sign(large_msg.data(), large_msg.size(),
                                         kp.privkey.data(), kp.pubkey.data());
    assert(flow::ed25519_verify(large_msg.data(), large_msg.size(),
                                 kp.pubkey.data(), large_sig.data()));
}
