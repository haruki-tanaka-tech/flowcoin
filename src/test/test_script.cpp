// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// "Script" verification in FlowCoin is Ed25519 signature verification
// over the transaction hash, with the signer's pubkey matching the
// UTXO's pubkey_hash. This test verifies the complete signing and
// verification flow used in transaction validation.

#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/transaction.h"
#include "util/types.h"
#include <cassert>
#include <cstring>
#include <stdexcept>

// Helper: compute pubkey hash (keccak256 of pubkey)
static std::array<uint8_t, 32> hash_pubkey(const std::array<uint8_t, 32>& pubkey) {
    auto h = flow::keccak256(pubkey.data(), 32);
    std::array<uint8_t, 32> result;
    std::memcpy(result.data(), h.data(), 32);
    return result;
}

void test_script() {
    auto kp_sender = flow::generate_keypair();
    auto kp_recipient = flow::generate_keypair();
    auto pkh_sender = hash_pubkey(kp_sender.pubkey);
    auto pkh_recipient = hash_pubkey(kp_recipient.pubkey);

    // Create a previous output that the sender owns
    flow::uint256 prev_txid;
    prev_txid[0] = 0x42;
    prev_txid[1] = 0x43;

    // Build a transaction spending that output
    flow::CTransaction tx;
    flow::CTxIn input;
    input.prevout = flow::COutPoint(prev_txid, 0);
    std::memcpy(input.pubkey.data(), kp_sender.pubkey.data(), 32);
    tx.vin.push_back(input);
    tx.vout.push_back(flow::CTxOut(10 * flow::COIN, pkh_recipient));

    // Compute the txid (this is what gets signed)
    auto txid = tx.get_txid();

    // Sign the txid with sender's private key
    auto sig = flow::ed25519_sign(txid.data(), txid.size(),
                                   kp_sender.privkey.data(),
                                   kp_sender.pubkey.data());
    std::memcpy(tx.vin[0].signature.data(), sig.data(), 64);

    // --- Verification: valid signature ---
    // This is exactly what consensus/validation.cpp does for non-coinbase inputs
    auto verify_txid = tx.get_txid();
    bool valid = flow::ed25519_verify(
        verify_txid.data(), verify_txid.size(),
        tx.vin[0].pubkey.data(),
        tx.vin[0].signature.data());
    assert(valid);

    // --- Verification: pubkey matches pkh ---
    // In a real node, we'd check that keccak256(input.pubkey) == utxo.pubkey_hash
    auto computed_pkh = hash_pubkey(kp_sender.pubkey);
    assert(computed_pkh == pkh_sender);

    // --- Invalid: wrong signer ---
    // If someone tries to sign with a different key
    {
        flow::CTransaction bad_tx = tx;
        auto bad_sig = flow::ed25519_sign(txid.data(), txid.size(),
                                           kp_recipient.privkey.data(),
                                           kp_recipient.pubkey.data());
        std::memcpy(bad_tx.vin[0].signature.data(), bad_sig.data(), 64);
        // The pubkey in the input is still sender's, but sig is from recipient
        auto bad_txid = bad_tx.get_txid();
        assert(!flow::ed25519_verify(
            bad_txid.data(), bad_txid.size(),
            bad_tx.vin[0].pubkey.data(),
            bad_tx.vin[0].signature.data()));
    }

    // --- Invalid: tampered transaction ---
    // Changing the output after signing should invalidate the signature
    {
        flow::CTransaction tampered_tx = tx;
        tampered_tx.vout[0].amount = 20 * flow::COIN;  // changed amount
        auto tampered_txid = tampered_tx.get_txid();
        // The signature was over the original txid, not the tampered one
        assert(tampered_txid != txid);
        assert(!flow::ed25519_verify(
            tampered_txid.data(), tampered_txid.size(),
            tampered_tx.vin[0].pubkey.data(),
            tampered_tx.vin[0].signature.data()));
    }

    // --- Invalid: corrupted signature ---
    {
        flow::CTransaction corrupt_tx = tx;
        corrupt_tx.vin[0].signature[32] ^= 0xFF;
        auto corrupt_txid = corrupt_tx.get_txid();
        assert(!flow::ed25519_verify(
            corrupt_txid.data(), corrupt_txid.size(),
            corrupt_tx.vin[0].pubkey.data(),
            corrupt_tx.vin[0].signature.data()));
    }

    // --- Invalid: pubkey hash mismatch ---
    // Even if the signature is valid, the pubkey must hash to the UTXO's pkh
    {
        auto wrong_pkh = hash_pubkey(kp_recipient.pubkey);
        // Sender's pubkey doesn't hash to recipient's pkh
        assert(pkh_sender != wrong_pkh);
    }

    // --- Multiple inputs: each must be signed independently ---
    {
        auto kp_alice = flow::generate_keypair();
        auto kp_bob = flow::generate_keypair();
        auto pkh_charlie = hash_pubkey(flow::generate_keypair().pubkey);

        flow::uint256 prev1, prev2;
        prev1[0] = 0xAA;
        prev2[0] = 0xBB;

        flow::CTransaction multi_tx;

        // Input 0: from Alice
        flow::CTxIn in0;
        in0.prevout = flow::COutPoint(prev1, 0);
        std::memcpy(in0.pubkey.data(), kp_alice.pubkey.data(), 32);
        multi_tx.vin.push_back(in0);

        // Input 1: from Bob
        flow::CTxIn in1;
        in1.prevout = flow::COutPoint(prev2, 0);
        std::memcpy(in1.pubkey.data(), kp_bob.pubkey.data(), 32);
        multi_tx.vin.push_back(in1);

        // Single output to Charlie
        multi_tx.vout.push_back(flow::CTxOut(100 * flow::COIN, pkh_charlie));

        // Compute txid
        auto multi_txid = multi_tx.get_txid();

        // Sign each input with the correct key
        auto sig0 = flow::ed25519_sign(multi_txid.data(), multi_txid.size(),
                                        kp_alice.privkey.data(),
                                        kp_alice.pubkey.data());
        std::memcpy(multi_tx.vin[0].signature.data(), sig0.data(), 64);

        auto sig1 = flow::ed25519_sign(multi_txid.data(), multi_txid.size(),
                                        kp_bob.privkey.data(),
                                        kp_bob.pubkey.data());
        std::memcpy(multi_tx.vin[1].signature.data(), sig1.data(), 64);

        // Both signatures should verify
        auto final_txid = multi_tx.get_txid();
        assert(flow::ed25519_verify(
            final_txid.data(), final_txid.size(),
            multi_tx.vin[0].pubkey.data(),
            multi_tx.vin[0].signature.data()));
        assert(flow::ed25519_verify(
            final_txid.data(), final_txid.size(),
            multi_tx.vin[1].pubkey.data(),
            multi_tx.vin[1].signature.data()));

        // Swapping signatures should fail
        assert(!flow::ed25519_verify(
            final_txid.data(), final_txid.size(),
            multi_tx.vin[0].pubkey.data(),
            multi_tx.vin[1].signature.data()));
        assert(!flow::ed25519_verify(
            final_txid.data(), final_txid.size(),
            multi_tx.vin[1].pubkey.data(),
            multi_tx.vin[0].signature.data()));
    }

    // --- Signature does not cover itself (no malleability) ---
    // The txid is computed from serialize_for_hash which excludes signatures.
    // Changing the signature bytes should not change the txid.
    {
        flow::CTransaction tx_copy = tx;
        auto txid_before = tx_copy.get_txid();
        tx_copy.vin[0].signature[0] ^= 0x01;
        auto txid_after = tx_copy.get_txid();
        assert(txid_before == txid_after);
    }
}
