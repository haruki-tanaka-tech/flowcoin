// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Benchmarks for Ed25519 key generation, signing, verification,
// batch verification, and SLIP-0010 HD key derivation.

#include "bench.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "crypto/slip0010.h"

#include <array>
#include <cstring>
#include <vector>

namespace flow::bench {

// ===========================================================================
// Key generation
// ===========================================================================

BENCH(Ed25519_KeyGen) {
    for (int i = 0; i < _iterations; i++) {
        KeyPair kp = generate_keypair();
        // Prevent dead-code elimination
        if (kp.pubkey[0] == 0xFF && kp.pubkey[1] == 0xFF) {
            kp.wipe();
        }
    }
}

BENCH(Ed25519_KeyGen_FromSeed) {
    uint8_t seed[32];
    std::memset(seed, 0x42, 32);
    for (int i = 0; i < _iterations; i++) {
        seed[0] = static_cast<uint8_t>(i & 0xFF);
        KeyPair kp = generate_keypair_from_seed(seed, 32);
        (void)kp;
    }
}

BENCH(Ed25519_DerivePubkey) {
    uint8_t privkey[32];
    std::memset(privkey, 0x37, 32);
    for (int i = 0; i < _iterations; i++) {
        privkey[0] = static_cast<uint8_t>(i & 0xFF);
        auto pubkey = derive_pubkey(privkey);
        (void)pubkey;
    }
}

// ===========================================================================
// Signing
// ===========================================================================

BENCH(Ed25519_Sign_32B) {
    KeyPair kp = generate_keypair();
    uint8_t msg[32];
    std::memset(msg, 0xAB, 32);
    for (int i = 0; i < _iterations; i++) {
        msg[0] = static_cast<uint8_t>(i & 0xFF);
        auto sig = ed25519_sign(msg, 32, kp.privkey.data(), kp.pubkey.data());
        (void)sig;
    }
}

BENCH(Ed25519_Sign_256B) {
    KeyPair kp = generate_keypair();
    std::vector<uint8_t> msg(256, 0xCD);
    for (int i = 0; i < _iterations; i++) {
        msg[0] = static_cast<uint8_t>(i & 0xFF);
        auto sig = ed25519_sign(msg.data(), msg.size(), kp.privkey.data(), kp.pubkey.data());
        (void)sig;
    }
}

BENCH(Ed25519_Sign_1KB) {
    KeyPair kp = generate_keypair();
    std::vector<uint8_t> msg(1024, 0xEF);
    for (int i = 0; i < _iterations; i++) {
        msg[0] = static_cast<uint8_t>(i & 0xFF);
        auto sig = ed25519_sign(msg.data(), msg.size(), kp.privkey.data(), kp.pubkey.data());
        (void)sig;
    }
}

BENCH(Ed25519_SignHash) {
    KeyPair kp = generate_keypair();
    uint8_t hash[32];
    std::memset(hash, 0xBE, 32);
    for (int i = 0; i < _iterations; i++) {
        hash[0] = static_cast<uint8_t>(i & 0xFF);
        auto sig = ed25519_sign_hash(hash, kp.privkey.data(), kp.pubkey.data());
        (void)sig;
    }
}

// ===========================================================================
// Verification
// ===========================================================================

BENCH(Ed25519_Verify_32B) {
    KeyPair kp = generate_keypair();
    uint8_t msg[32];
    std::memset(msg, 0xAB, 32);
    auto sig = ed25519_sign(msg, 32, kp.privkey.data(), kp.pubkey.data());
    for (int i = 0; i < _iterations; i++) {
        bool ok = ed25519_verify(msg, 32, kp.pubkey.data(), sig.data());
        if (!ok) break;
    }
}

BENCH(Ed25519_Verify_1KB) {
    KeyPair kp = generate_keypair();
    std::vector<uint8_t> msg(1024, 0xEF);
    auto sig = ed25519_sign(msg.data(), msg.size(), kp.privkey.data(), kp.pubkey.data());
    for (int i = 0; i < _iterations; i++) {
        bool ok = ed25519_verify(msg.data(), msg.size(), kp.pubkey.data(), sig.data());
        if (!ok) break;
    }
}

BENCH(Ed25519_VerifyHash) {
    KeyPair kp = generate_keypair();
    uint8_t hash[32];
    std::memset(hash, 0xBE, 32);
    auto sig = ed25519_sign_hash(hash, kp.privkey.data(), kp.pubkey.data());
    for (int i = 0; i < _iterations; i++) {
        bool ok = ed25519_verify_hash(hash, kp.pubkey.data(), sig.data());
        if (!ok) break;
    }
}

// ===========================================================================
// Batch verification
// ===========================================================================

BENCH(Ed25519_BatchVerify_10) {
    constexpr int BATCH = 10;
    std::vector<KeyPair> keys(BATCH);
    std::vector<std::vector<uint8_t>> msgs(BATCH);
    std::vector<std::array<uint8_t, 64>> sigs(BATCH);

    for (int j = 0; j < BATCH; j++) {
        keys[j] = generate_keypair();
        msgs[j].resize(64);
        std::memset(msgs[j].data(), static_cast<int>(j + 1), 64);
        sigs[j] = ed25519_sign(msgs[j].data(), msgs[j].size(),
                               keys[j].privkey.data(), keys[j].pubkey.data());
    }

    std::vector<const uint8_t*> msg_ptrs(BATCH);
    std::vector<size_t> msg_lens(BATCH);
    std::vector<const uint8_t*> pub_ptrs(BATCH);
    std::vector<const uint8_t*> sig_ptrs(BATCH);

    for (int j = 0; j < BATCH; j++) {
        msg_ptrs[j] = msgs[j].data();
        msg_lens[j] = msgs[j].size();
        pub_ptrs[j] = keys[j].pubkey.data();
        sig_ptrs[j] = sigs[j].data();
    }

    for (int i = 0; i < _iterations; i++) {
        bool ok = ed25519_verify_batch(
            msg_ptrs.data(), msg_lens.data(),
            pub_ptrs.data(), sig_ptrs.data(), BATCH);
        if (!ok) break;
    }
}

BENCH(Ed25519_BatchVerify_100) {
    constexpr int BATCH = 100;
    std::vector<KeyPair> keys(BATCH);
    std::vector<std::vector<uint8_t>> msgs(BATCH);
    std::vector<std::array<uint8_t, 64>> sigs(BATCH);

    for (int j = 0; j < BATCH; j++) {
        keys[j] = generate_keypair();
        msgs[j].resize(64);
        std::memset(msgs[j].data(), static_cast<int>(j % 256), 64);
        sigs[j] = ed25519_sign(msgs[j].data(), msgs[j].size(),
                               keys[j].privkey.data(), keys[j].pubkey.data());
    }

    std::vector<const uint8_t*> msg_ptrs(BATCH);
    std::vector<size_t> msg_lens(BATCH);
    std::vector<const uint8_t*> pub_ptrs(BATCH);
    std::vector<const uint8_t*> sig_ptrs(BATCH);

    for (int j = 0; j < BATCH; j++) {
        msg_ptrs[j] = msgs[j].data();
        msg_lens[j] = msgs[j].size();
        pub_ptrs[j] = keys[j].pubkey.data();
        sig_ptrs[j] = sigs[j].data();
    }

    for (int i = 0; i < _iterations; i++) {
        bool ok = ed25519_verify_batch(
            msg_ptrs.data(), msg_lens.data(),
            pub_ptrs.data(), sig_ptrs.data(), BATCH);
        if (!ok) break;
    }
}

// ===========================================================================
// SLIP-0010 HD key derivation
// ===========================================================================

BENCH(SLIP0010_Master) {
    uint8_t seed[64];
    std::memset(seed, 0x55, 64);
    for (int i = 0; i < _iterations; i++) {
        seed[0] = static_cast<uint8_t>(i & 0xFF);
        ExtendedKey master = slip0010_master(seed, 64);
        (void)master;
    }
}

BENCH(SLIP0010_DeriveHardened) {
    uint8_t seed[64];
    std::memset(seed, 0x55, 64);
    ExtendedKey parent = slip0010_master(seed, 64);
    for (int i = 0; i < _iterations; i++) {
        ExtendedKey child = slip0010_derive_hardened(parent, static_cast<uint32_t>(i));
        (void)child;
    }
}

BENCH(SLIP0010_FullPath) {
    uint8_t seed[64];
    std::memset(seed, 0x55, 64);
    for (int i = 0; i < _iterations; i++) {
        seed[0] = static_cast<uint8_t>(i & 0xFF);
        ExtendedKey key = slip0010_derive_path(seed, 64, static_cast<uint32_t>(i));
        (void)key;
    }
}

BENCH(SLIP0010_DeriveKeypair) {
    uint8_t seed[64];
    std::memset(seed, 0x55, 64);
    for (int i = 0; i < _iterations; i++) {
        KeyPair kp = derive_keypair(seed, 64, static_cast<uint32_t>(i));
        (void)kp;
    }
}

// ===========================================================================
// SecurePrivKey / SecurePubKey container operations
// ===========================================================================

BENCH(SecurePrivKey_Create) {
    for (int i = 0; i < _iterations; i++) {
        KeyPair kp = generate_keypair();
        SecurePrivKey sk(kp.privkey.data());
        if (!sk.is_valid()) break;
    }
}

BENCH(SecurePrivKey_DerivePubkey) {
    KeyPair kp = generate_keypair();
    SecurePrivKey sk(kp.privkey.data());
    for (int i = 0; i < _iterations; i++) {
        auto pk = sk.derive_pubkey();
        (void)pk;
    }
}

BENCH(SecurePrivKey_GetKeyId) {
    KeyPair kp = generate_keypair();
    SecurePrivKey sk(kp.privkey.data());
    for (int i = 0; i < _iterations; i++) {
        auto kid = sk.get_key_id();
        if (kid.empty()) break;
    }
}

BENCH(SecurePrivKey_ToHex) {
    KeyPair kp = generate_keypair();
    SecurePrivKey sk(kp.privkey.data());
    for (int i = 0; i < _iterations; i++) {
        std::string hex = sk.to_hex();
        if (hex.empty()) break;
    }
}

BENCH(SecurePubKey_GetId) {
    KeyPair kp = generate_keypair();
    SecurePubKey pk(kp.pubkey.data());
    for (int i = 0; i < _iterations; i++) {
        auto kid = pk.get_id();
        if (kid.empty()) break;
    }
}

BENCH(SecurePubKey_GetHash) {
    KeyPair kp = generate_keypair();
    SecurePubKey pk(kp.pubkey.data());
    for (int i = 0; i < _iterations; i++) {
        uint256 h = pk.get_hash();
        (void)h;
    }
}

// ===========================================================================
// Key export/import with checksum
// ===========================================================================

BENCH(ExportPrivkeyHex) {
    KeyPair kp = generate_keypair();
    for (int i = 0; i < _iterations; i++) {
        std::string hex = export_privkey_hex(kp.privkey.data());
        if (hex.empty()) break;
    }
}

BENCH(ImportPrivkeyHex) {
    KeyPair kp = generate_keypair();
    std::string hex = export_privkey_hex(kp.privkey.data());
    for (int i = 0; i < _iterations; i++) {
        std::array<uint8_t, 32> imported;
        bool ok = import_privkey_hex(hex, imported);
        if (!ok) break;
    }
}

// ===========================================================================
// Batch keypair derivation
// ===========================================================================

BENCH(SLIP0010_BatchDerive_10) {
    uint8_t seed[64];
    std::memset(seed, 0x55, 64);
    for (int i = 0; i < _iterations; i++) {
        seed[0] = static_cast<uint8_t>(i & 0xFF);
        auto batch = derive_keypair_batch(seed, 64, 0, 10);
        if (batch.size() != 10) break;
    }
}

BENCH(SLIP0010_BatchDerive_100) {
    uint8_t seed[64];
    std::memset(seed, 0x55, 64);
    for (int i = 0; i < _iterations; i++) {
        seed[0] = static_cast<uint8_t>(i & 0xFF);
        auto batch = derive_keypair_batch(seed, 64, 0, 100);
        if (batch.size() != 100) break;
    }
}

BENCH(SLIP0010_ParseDerivationPath) {
    std::string path = "m/44'/9555'/0'/0'/0'";
    for (int i = 0; i < _iterations; i++) {
        std::vector<uint32_t> indices;
        bool ok = parse_derivation_path(path, indices);
        if (!ok) break;
    }
}

// ===========================================================================
// Signature validation
// ===========================================================================

BENCH(Ed25519_IsValidSignature) {
    KeyPair kp = generate_keypair();
    uint8_t msg[32];
    std::memset(msg, 0xAB, 32);
    auto sig = ed25519_sign(msg, 32, kp.privkey.data(), kp.pubkey.data());

    for (int i = 0; i < _iterations; i++) {
        bool ok = is_valid_signature(sig.data());
        (void)ok;
    }
}

// ===========================================================================
// Constant-time comparison
// ===========================================================================

BENCH(ConstantTimeCompare_32B) {
    uint8_t a[32], b[32];
    std::memset(a, 0xAA, 32);
    std::memset(b, 0xAA, 32);
    for (int i = 0; i < _iterations; i++) {
        bool eq = constant_time_compare(a, b, 32);
        (void)eq;
    }
}

BENCH(SecureWipe_32B) {
    uint8_t data[32];
    std::memset(data, 0xFF, 32);
    for (int i = 0; i < _iterations; i++) {
        std::memset(data, 0xFF, 32);
        secure_wipe(data, 32);
    }
}

BENCH(SecureRandom_32B) {
    uint8_t buf[32];
    for (int i = 0; i < _iterations; i++) {
        secure_random(buf, 32);
    }
}

} // namespace flow::bench
