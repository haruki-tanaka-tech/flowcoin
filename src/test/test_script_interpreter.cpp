// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Comprehensive tests for the script verification system including
// P2PKH verification, script classification, sigop counting,
// script construction, and edge cases.

#include "script/script.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/transaction.h"
#include "util/random.h"
#include "util/types.h"

#include <cassert>
#include <cstring>
#include <stdexcept>
#include <vector>

using namespace flow;

// Helper: compute pubkey hash (keccak256d of pubkey)
static std::array<uint8_t, 32> pkh(const std::array<uint8_t, 32>& pubkey) {
    uint256 h = keccak256d(pubkey.data(), 32);
    std::array<uint8_t, 32> result;
    std::memcpy(result.data(), h.data(), 32);
    return result;
}

// Helper: build a signed transaction and return its txid + sig for script testing
static void sign_tx(CTransaction& tx, const KeyPair& kp, size_t input_idx) {
    auto txid = tx.get_txid();
    auto sig = ed25519_sign(txid.data(), txid.size(),
                             kp.privkey.data(), kp.pubkey.data());
    std::memcpy(tx.vin[input_idx].signature.data(), sig.data(), 64);
}

void test_script_interpreter() {
    // -----------------------------------------------------------------------
    // Test 1: P2PKH script: valid signature + pubkey → true
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pubkey_hash = pkh(kp.pubkey);

        // Create script_pubkey (P2PKH = just the 32-byte pubkey hash)
        auto script_pk = script::make_p2pkh(pubkey_hash);
        assert(script_pk.size() == 32);

        // Build a transaction to sign
        CTransaction tx;
        CTxIn in;
        uint256 prev_txid;
        prev_txid[0] = 0x42;
        in.prevout = COutPoint(prev_txid, 0);
        std::memcpy(in.pubkey.data(), kp.pubkey.data(), 32);
        tx.vin.push_back(in);
        tx.vout.push_back(CTxOut(10 * COIN, pubkey_hash));

        auto tx_hash = tx.get_txid();

        // Sign it
        auto sig = ed25519_sign(tx_hash.data(), tx_hash.size(),
                                 kp.privkey.data(), kp.pubkey.data());

        // Build script_sig: [64 sig][32 pubkey]
        auto script_sig = script::make_script_sig(sig.data(), kp.pubkey.data());
        assert(script_sig.size() == 96);

        // Verify
        bool valid = script::verify_script(script_sig, script_pk, tx_hash);
        assert(valid);
    }

    // -----------------------------------------------------------------------
    // Test 2: P2PKH: invalid signature → false
    // -----------------------------------------------------------------------
    {
        auto kp_signer = generate_keypair();
        auto kp_other = generate_keypair();
        auto pubkey_hash = pkh(kp_signer.pubkey);
        auto script_pk = script::make_p2pkh(pubkey_hash);

        CTransaction tx;
        CTxIn in;
        uint256 prev_txid;
        prev_txid[0] = 0x55;
        in.prevout = COutPoint(prev_txid, 0);
        std::memcpy(in.pubkey.data(), kp_signer.pubkey.data(), 32);
        tx.vin.push_back(in);
        tx.vout.push_back(CTxOut(5 * COIN, pubkey_hash));

        auto tx_hash = tx.get_txid();

        // Sign with wrong key
        auto bad_sig = ed25519_sign(tx_hash.data(), tx_hash.size(),
                                     kp_other.privkey.data(), kp_other.pubkey.data());

        // Use signer's pubkey but other's signature
        auto script_sig = script::make_script_sig(bad_sig.data(), kp_signer.pubkey.data());
        bool valid = script::verify_script(script_sig, script_pk, tx_hash);
        assert(!valid);
    }

    // -----------------------------------------------------------------------
    // Test 3: P2PKH: wrong pubkey (hash mismatch) → false
    // -----------------------------------------------------------------------
    {
        auto kp_signer = generate_keypair();
        auto kp_other = generate_keypair();
        auto pubkey_hash = pkh(kp_signer.pubkey);
        auto script_pk = script::make_p2pkh(pubkey_hash);

        CTransaction tx;
        CTxIn in;
        uint256 prev_txid;
        prev_txid[0] = 0x66;
        in.prevout = COutPoint(prev_txid, 0);
        std::memcpy(in.pubkey.data(), kp_other.pubkey.data(), 32);
        tx.vin.push_back(in);
        tx.vout.push_back(CTxOut(5 * COIN, pubkey_hash));

        auto tx_hash = tx.get_txid();

        // Sign with other's key (valid sig for other's pubkey, but wrong pubkey hash)
        auto sig = ed25519_sign(tx_hash.data(), tx_hash.size(),
                                 kp_other.privkey.data(), kp_other.pubkey.data());

        auto script_sig = script::make_script_sig(sig.data(), kp_other.pubkey.data());
        bool valid = script::verify_script(script_sig, script_pk, tx_hash);
        assert(!valid);  // pubkey hash won't match
    }

    // -----------------------------------------------------------------------
    // Test 4: Script classification - P2PKH (32 bytes)
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> script_32(32, 0xAB);
        assert(script::classify(script_32) == script::ScriptType::P2PKH);
    }

    // -----------------------------------------------------------------------
    // Test 5: Script classification - EMPTY
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> empty;
        assert(script::classify(empty) == script::ScriptType::EMPTY);
    }

    // -----------------------------------------------------------------------
    // Test 6: Script classification - COINBASE (non-32 bytes, non-empty)
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> coinbase_data = {0x01, 0x02, 0x03};
        assert(script::classify(coinbase_data) == script::ScriptType::COINBASE);

        std::vector<uint8_t> long_data(64, 0xFF);
        assert(script::classify(long_data) == script::ScriptType::COINBASE);
    }

    // -----------------------------------------------------------------------
    // Test 7: make_p2pkh from array
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> hash;
        GetRandBytes(hash.data(), 32);

        auto script = script::make_p2pkh(hash);
        assert(script.size() == 32);
        assert(std::memcmp(script.data(), hash.data(), 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 8: make_p2pkh from vector (valid)
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> hash(32, 0xCC);
        auto script = script::make_p2pkh(hash);
        assert(script.size() == 32);
        assert(script == hash);
    }

    // -----------------------------------------------------------------------
    // Test 9: make_p2pkh from vector (invalid size)
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> short_hash(16, 0xDD);
        auto script = script::make_p2pkh(short_hash);
        assert(script.empty());
    }

    // -----------------------------------------------------------------------
    // Test 10: make_p2pkh_from_pubkey hashes the pubkey
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto script = script::make_p2pkh_from_pubkey(kp.pubkey.data());
        assert(script.size() == 32);

        // Should equal keccak256d(pubkey)
        uint256 expected = keccak256d(kp.pubkey.data(), 32);
        assert(std::memcmp(script.data(), expected.data(), 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 11: extract_pubkey_hash (vector return)
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> p2pkh(32, 0xEE);
        auto extracted = script::extract_pubkey_hash(p2pkh);
        assert(extracted.size() == 32);
        assert(extracted == p2pkh);
    }

    // -----------------------------------------------------------------------
    // Test 12: extract_pubkey_hash from non-P2PKH returns empty
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> not_p2pkh(33, 0xFF);
        auto extracted = script::extract_pubkey_hash(not_p2pkh);
        assert(extracted.empty());
    }

    // -----------------------------------------------------------------------
    // Test 13: extract_pubkey_hash (array output)
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> p2pkh(32, 0xAA);
        std::array<uint8_t, 32> out;
        bool ok = script::extract_pubkey_hash(p2pkh, out);
        assert(ok);
        assert(std::memcmp(out.data(), p2pkh.data(), 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 14: extract_pubkey_hash (array output, invalid)
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> not_p2pkh(31, 0xBB);
        std::array<uint8_t, 32> out;
        bool ok = script::extract_pubkey_hash(not_p2pkh, out);
        assert(!ok);
    }

    // -----------------------------------------------------------------------
    // Test 15: make_script_sig constructs 96-byte result
    // -----------------------------------------------------------------------
    {
        uint8_t sig[64], pubkey[32];
        std::memset(sig, 0x11, 64);
        std::memset(pubkey, 0x22, 32);

        auto script_sig = script::make_script_sig(sig, pubkey);
        assert(script_sig.size() == 96);
        assert(std::memcmp(script_sig.data(), sig, 64) == 0);
        assert(std::memcmp(script_sig.data() + 64, pubkey, 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 16: parse_script_sig extracts sig and pubkey
    // -----------------------------------------------------------------------
    {
        uint8_t sig[64], pk[32];
        std::memset(sig, 0x33, 64);
        std::memset(pk, 0x44, 32);

        auto script_sig = script::make_script_sig(sig, pk);
        const uint8_t* sig_out = nullptr;
        const uint8_t* pk_out = nullptr;

        bool ok = script::parse_script_sig(script_sig, sig_out, pk_out);
        assert(ok);
        assert(std::memcmp(sig_out, sig, 64) == 0);
        assert(std::memcmp(pk_out, pk, 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 17: parse_script_sig rejects wrong-size input
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> bad(95, 0x00);
        const uint8_t* sig_out = nullptr;
        const uint8_t* pk_out = nullptr;
        assert(!script::parse_script_sig(bad, sig_out, pk_out));

        std::vector<uint8_t> bad2(97, 0x00);
        assert(!script::parse_script_sig(bad2, sig_out, pk_out));
    }

    // -----------------------------------------------------------------------
    // Test 18: verify_script rejects wrong-size scriptSig
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> bad_sig(95, 0x00);
        std::vector<uint8_t> script_pk(32, 0xAA);
        uint256 tx_hash;

        assert(!script::verify_script(bad_sig, script_pk, tx_hash));
    }

    // -----------------------------------------------------------------------
    // Test 19: verify_script rejects wrong-size scriptPubKey
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> script_sig(96, 0x00);
        std::vector<uint8_t> bad_pk(31, 0xBB);
        uint256 tx_hash;

        assert(!script::verify_script(script_sig, bad_pk, tx_hash));
    }

    // -----------------------------------------------------------------------
    // Test 20: count_sigops for P2PKH script = 1
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> p2pkh(32, 0xCC);
        assert(script::count_sigops(p2pkh) == 1);
    }

    // -----------------------------------------------------------------------
    // Test 21: count_sigops for non-P2PKH script = 0
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> empty;
        assert(script::count_sigops(empty) == 0);

        std::vector<uint8_t> coinbase(10, 0x42);
        assert(script::count_sigops(coinbase) == 0);

        std::vector<uint8_t> long_script(64, 0xFF);
        assert(script::count_sigops(long_script) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 22: Corrupted signature in script_sig fails verification
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pubkey_hash = pkh(kp.pubkey);
        auto script_pk = script::make_p2pkh(pubkey_hash);

        uint256 tx_hash = GetRandUint256();
        auto sig = ed25519_sign(tx_hash.data(), tx_hash.size(),
                                 kp.privkey.data(), kp.pubkey.data());

        auto script_sig = script::make_script_sig(sig.data(), kp.pubkey.data());

        // Verify it works first
        assert(script::verify_script(script_sig, script_pk, tx_hash));

        // Corrupt one byte of the signature
        script_sig[32] ^= 0xFF;
        assert(!script::verify_script(script_sig, script_pk, tx_hash));
    }

    // -----------------------------------------------------------------------
    // Test 23: Multiple inputs each verified independently
    // -----------------------------------------------------------------------
    {
        auto kp_alice = generate_keypair();
        auto kp_bob = generate_keypair();
        auto pkh_charlie = pkh(generate_keypair().pubkey);

        uint256 prev1, prev2;
        prev1[0] = 0xAA;
        prev2[0] = 0xBB;

        CTransaction multi_tx;

        CTxIn in0;
        in0.prevout = COutPoint(prev1, 0);
        std::memcpy(in0.pubkey.data(), kp_alice.pubkey.data(), 32);
        multi_tx.vin.push_back(in0);

        CTxIn in1;
        in1.prevout = COutPoint(prev2, 0);
        std::memcpy(in1.pubkey.data(), kp_bob.pubkey.data(), 32);
        multi_tx.vin.push_back(in1);

        multi_tx.vout.push_back(CTxOut(100 * COIN, pkh_charlie));

        auto txid = multi_tx.get_txid();

        // Sign each input
        auto sig0 = ed25519_sign(txid.data(), txid.size(),
                                  kp_alice.privkey.data(), kp_alice.pubkey.data());
        std::memcpy(multi_tx.vin[0].signature.data(), sig0.data(), 64);

        auto sig1 = ed25519_sign(txid.data(), txid.size(),
                                  kp_bob.privkey.data(), kp_bob.pubkey.data());
        std::memcpy(multi_tx.vin[1].signature.data(), sig1.data(), 64);

        // Verify each script independently
        auto script_pk_alice = script::make_p2pkh(pkh(kp_alice.pubkey));
        auto script_sig_alice = script::make_script_sig(
            multi_tx.vin[0].signature.data(), multi_tx.vin[0].pubkey.data());
        auto final_txid = multi_tx.get_txid();
        assert(script::verify_script(script_sig_alice, script_pk_alice, final_txid));

        auto script_pk_bob = script::make_p2pkh(pkh(kp_bob.pubkey));
        auto script_sig_bob = script::make_script_sig(
            multi_tx.vin[1].signature.data(), multi_tx.vin[1].pubkey.data());
        assert(script::verify_script(script_sig_bob, script_pk_bob, final_txid));

        // Swapping signatures fails
        assert(!script::verify_script(script_sig_bob, script_pk_alice, final_txid));
        assert(!script::verify_script(script_sig_alice, script_pk_bob, final_txid));
    }

    // -----------------------------------------------------------------------
    // Test 24: Signature does not cover itself (txid excludes sig bytes)
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pub_hash = pkh(kp.pubkey);

        CTransaction tx;
        CTxIn in;
        uint256 prev;
        prev[0] = 0xCC;
        in.prevout = COutPoint(prev, 0);
        std::memcpy(in.pubkey.data(), kp.pubkey.data(), 32);
        tx.vin.push_back(in);
        tx.vout.push_back(CTxOut(5 * COIN, pub_hash));

        auto txid1 = tx.get_txid();

        // Change the signature bytes
        tx.vin[0].signature[0] ^= 0x01;
        auto txid2 = tx.get_txid();

        // txid should be the same (signatures are excluded from hash)
        assert(txid1 == txid2);
    }

    // -----------------------------------------------------------------------
    // Test 25: Empty scriptSig fails
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> empty_sig;
        std::vector<uint8_t> script_pk(32, 0xDD);
        uint256 hash;
        assert(!script::verify_script(empty_sig, script_pk, hash));
    }

    // -----------------------------------------------------------------------
    // Test 26: Empty scriptPubKey fails
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> script_sig(96, 0x00);
        std::vector<uint8_t> empty_pk;
        uint256 hash;
        assert(!script::verify_script(script_sig, empty_pk, hash));
    }

    // -----------------------------------------------------------------------
    // Test 27: All-zero tx_hash still works with valid sig
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pub_hash = pkh(kp.pubkey);
        auto script_pk = script::make_p2pkh(pub_hash);

        uint256 zero_hash;  // all zeros

        auto sig = ed25519_sign(zero_hash.data(), zero_hash.size(),
                                 kp.privkey.data(), kp.pubkey.data());
        auto script_sig = script::make_script_sig(sig.data(), kp.pubkey.data());

        assert(script::verify_script(script_sig, script_pk, zero_hash));
    }

    // -----------------------------------------------------------------------
    // Test 28: Verify multiple different tx hashes with same key
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pub_hash = pkh(kp.pubkey);
        auto script_pk = script::make_p2pkh(pub_hash);

        for (int i = 0; i < 10; ++i) {
            uint256 tx_hash = GetRandUint256();
            auto sig = ed25519_sign(tx_hash.data(), tx_hash.size(),
                                     kp.privkey.data(), kp.pubkey.data());
            auto script_sig = script::make_script_sig(sig.data(), kp.pubkey.data());
            assert(script::verify_script(script_sig, script_pk, tx_hash));
        }
    }

    // -----------------------------------------------------------------------
    // Test 29: Classify all-ones 32 bytes as P2PKH
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> all_ones(32, 0xFF);
        assert(script::classify(all_ones) == script::ScriptType::P2PKH);
    }

    // -----------------------------------------------------------------------
    // Test 30: make_p2pkh_from_pubkey produces consistent results
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto s1 = script::make_p2pkh_from_pubkey(kp.pubkey.data());
        auto s2 = script::make_p2pkh_from_pubkey(kp.pubkey.data());
        assert(s1 == s2);
        assert(s1.size() == 32);
    }

    // -----------------------------------------------------------------------
    // Test 31: Different pubkeys produce different P2PKH scripts
    // -----------------------------------------------------------------------
    {
        auto kp1 = generate_keypair();
        auto kp2 = generate_keypair();

        auto s1 = script::make_p2pkh_from_pubkey(kp1.pubkey.data());
        auto s2 = script::make_p2pkh_from_pubkey(kp2.pubkey.data());

        assert(s1 != s2);
    }

    // -----------------------------------------------------------------------
    // Test 32: Verify with random data in scriptSig fails gracefully
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> random_sig(96);
        GetRandBytes(random_sig.data(), 96);

        std::vector<uint8_t> random_pk(32);
        GetRandBytes(random_pk.data(), 32);

        uint256 tx_hash = GetRandUint256();

        // Random data should fail verification (extremely unlikely to be valid)
        bool result = script::verify_script(random_sig, random_pk, tx_hash);
        assert(!result);
    }

    // -----------------------------------------------------------------------
    // Test 33: P2PKH verification with modified tx_hash fails
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pub_hash = pkh(kp.pubkey);
        auto script_pk = script::make_p2pkh(pub_hash);

        uint256 tx_hash = GetRandUint256();
        auto sig = ed25519_sign(tx_hash.data(), tx_hash.size(),
                                 kp.privkey.data(), kp.pubkey.data());
        auto script_sig = script::make_script_sig(sig.data(), kp.pubkey.data());

        // Verify passes with correct hash
        assert(script::verify_script(script_sig, script_pk, tx_hash));

        // Modify one byte of tx_hash
        uint256 modified_hash = tx_hash;
        modified_hash[0] ^= 0x01;
        assert(!script::verify_script(script_sig, script_pk, modified_hash));
    }

    // -----------------------------------------------------------------------
    // Test 34: Large batch of script verifications
    // -----------------------------------------------------------------------
    {
        for (int i = 0; i < 20; ++i) {
            auto kp = generate_keypair();
            auto pub_hash = pkh(kp.pubkey);
            auto script_pk = script::make_p2pkh(pub_hash);

            uint256 tx_hash = GetRandUint256();
            auto sig = ed25519_sign(tx_hash.data(), tx_hash.size(),
                                     kp.privkey.data(), kp.pubkey.data());
            auto script_sig = script::make_script_sig(sig.data(), kp.pubkey.data());

            assert(script::verify_script(script_sig, script_pk, tx_hash));
        }
    }

    // -----------------------------------------------------------------------
    // Test 35: Count sigops on various script sizes
    // -----------------------------------------------------------------------
    {
        // Exactly 32 bytes = P2PKH = 1 sigop
        for (int fill = 0; fill < 256; ++fill) {
            std::vector<uint8_t> s(32, static_cast<uint8_t>(fill));
            assert(script::count_sigops(s) == 1);
        }

        // Not 32 bytes = 0 sigops
        for (size_t sz : {0, 1, 16, 31, 33, 64, 96, 128}) {
            std::vector<uint8_t> s(sz, 0xFF);
            assert(script::count_sigops(s) == 0);
        }
    }

    // -----------------------------------------------------------------------
    // Test 36: Classify scripts of various sizes
    // -----------------------------------------------------------------------
    {
        // Empty = EMPTY
        assert(script::classify(std::vector<uint8_t>{}) == script::ScriptType::EMPTY);

        // 32 bytes = P2PKH
        assert(script::classify(std::vector<uint8_t>(32, 0)) == script::ScriptType::P2PKH);

        // Anything else = COINBASE
        for (size_t sz : {1, 2, 5, 16, 31, 33, 64, 100, 256}) {
            assert(script::classify(std::vector<uint8_t>(sz, 0)) == script::ScriptType::COINBASE);
        }
    }

    // -----------------------------------------------------------------------
    // Test 37: make_p2pkh with all-zero hash
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> zero_hash{};
        auto script = script::make_p2pkh(zero_hash);
        assert(script.size() == 32);
        for (auto b : script) {
            assert(b == 0);
        }
    }

    // -----------------------------------------------------------------------
    // Test 38: extract_pubkey_hash from make_p2pkh round-trip
    // -----------------------------------------------------------------------
    {
        for (int i = 0; i < 10; ++i) {
            std::array<uint8_t, 32> hash;
            GetRandBytes(hash.data(), 32);

            auto script = script::make_p2pkh(hash);
            auto extracted = script::extract_pubkey_hash(script);

            assert(extracted.size() == 32);
            assert(std::memcmp(extracted.data(), hash.data(), 32) == 0);

            // Array variant
            std::array<uint8_t, 32> arr_out;
            assert(script::extract_pubkey_hash(script, arr_out));
            assert(arr_out == hash);
        }
    }

    // -----------------------------------------------------------------------
    // Test 39: parse_script_sig with exact 96 bytes
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> sig_data(96);
        GetRandBytes(sig_data.data(), 96);

        const uint8_t* sig_ptr = nullptr;
        const uint8_t* pk_ptr = nullptr;
        assert(script::parse_script_sig(sig_data, sig_ptr, pk_ptr));
        assert(sig_ptr == sig_data.data());
        assert(pk_ptr == sig_data.data() + 64);
    }

    // -----------------------------------------------------------------------
    // Test 40: Full transaction signing and script verification flow
    // -----------------------------------------------------------------------
    {
        // Create a complete transaction with multiple inputs and outputs
        auto kp_sender1 = generate_keypair();
        auto kp_sender2 = generate_keypair();
        auto kp_recipient = generate_keypair();

        auto pkh_s1 = pkh(kp_sender1.pubkey);
        auto pkh_s2 = pkh(kp_sender2.pubkey);
        auto pkh_r = pkh(kp_recipient.pubkey);

        CTransaction tx;
        uint256 prev1, prev2;
        prev1[0] = 0x11;
        prev2[0] = 0x22;

        CTxIn in1;
        in1.prevout = COutPoint(prev1, 0);
        std::memcpy(in1.pubkey.data(), kp_sender1.pubkey.data(), 32);
        tx.vin.push_back(in1);

        CTxIn in2;
        in2.prevout = COutPoint(prev2, 0);
        std::memcpy(in2.pubkey.data(), kp_sender2.pubkey.data(), 32);
        tx.vin.push_back(in2);

        tx.vout.push_back(CTxOut(50 * COIN, pkh_r));
        tx.vout.push_back(CTxOut(40 * COIN, pkh_s1));  // change

        auto txid = tx.get_txid();

        // Sign both inputs
        auto sig1 = ed25519_sign(txid.data(), txid.size(),
                                  kp_sender1.privkey.data(), kp_sender1.pubkey.data());
        std::memcpy(tx.vin[0].signature.data(), sig1.data(), 64);

        auto sig2 = ed25519_sign(txid.data(), txid.size(),
                                  kp_sender2.privkey.data(), kp_sender2.pubkey.data());
        std::memcpy(tx.vin[1].signature.data(), sig2.data(), 64);

        // Verify each input's script
        auto final_txid = tx.get_txid();

        auto script_sig1 = script::make_script_sig(
            tx.vin[0].signature.data(), tx.vin[0].pubkey.data());
        auto script_pk1 = script::make_p2pkh(pkh_s1);
        assert(script::verify_script(script_sig1, script_pk1, final_txid));

        auto script_sig2 = script::make_script_sig(
            tx.vin[1].signature.data(), tx.vin[1].pubkey.data());
        auto script_pk2 = script::make_p2pkh(pkh_s2);
        assert(script::verify_script(script_sig2, script_pk2, final_txid));

        // Cross-verify fails
        assert(!script::verify_script(script_sig1, script_pk2, final_txid));
        assert(!script::verify_script(script_sig2, script_pk1, final_txid));
    }
}
