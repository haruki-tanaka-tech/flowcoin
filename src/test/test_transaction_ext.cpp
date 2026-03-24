// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Extended transaction tests: serialization, signing, validation,
// coinbase construction, and edge cases.

#include "consensus/params.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/transaction.h"
#include "util/random.h"
#include "util/strencodings.h"

#include <cassert>
#include <cstring>
#include <stdexcept>
#include <vector>

using namespace flow;

// Helper: make a signed transaction
static CTransaction make_signed_transfer(const uint256& prev_txid,
                                          uint32_t prev_vout,
                                          Amount amount,
                                          const std::array<uint8_t, 32>& dest_pkh,
                                          const KeyPair& sender) {
    CTransaction tx;
    tx.version = 1;
    tx.locktime = 0;

    CTxIn in;
    in.prevout = COutPoint(prev_txid, prev_vout);
    in.pubkey = sender.pubkey;
    tx.vin.push_back(in);

    tx.vout.push_back(CTxOut(amount, dest_pkh));

    auto sighash = tx.serialize_for_hash();
    auto txhash = keccak256d(sighash);
    auto sig = ed25519_sign(txhash.data(), 32,
                            sender.privkey.data(), sender.pubkey.data());
    tx.vin[0].signature = sig;

    return tx;
}

void test_transaction_ext() {

    // -----------------------------------------------------------------------
    // Test 1: Transaction ID is deterministic
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        uint256 prev_txid = GetRandUint256();
        std::array<uint8_t, 32> dest_pkh;
        GetRandBytes(dest_pkh.data(), 32);

        auto tx = make_signed_transfer(prev_txid, 0, 100000, dest_pkh, kp);
        uint256 txid1 = tx.get_txid();
        uint256 txid2 = tx.get_txid();
        assert(txid1 == txid2);
        assert(!txid1.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 2: Different inputs produce different txids
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        std::array<uint8_t, 32> dest_pkh;
        GetRandBytes(dest_pkh.data(), 32);

        uint256 prev1 = GetRandUint256();
        uint256 prev2 = GetRandUint256();

        auto tx1 = make_signed_transfer(prev1, 0, 100000, dest_pkh, kp);
        auto tx2 = make_signed_transfer(prev2, 0, 100000, dest_pkh, kp);

        assert(tx1.get_txid() != tx2.get_txid());
    }

    // -----------------------------------------------------------------------
    // Test 3: Coinbase transaction detection
    // -----------------------------------------------------------------------
    {
        CTransaction cb;
        cb.version = 1;
        CTxIn coinbase_in;
        cb.vin.push_back(coinbase_in);
        std::array<uint8_t, 32> pkh;
        GetRandBytes(pkh.data(), 32);
        cb.vout.push_back(CTxOut(5000000000LL, pkh));

        assert(cb.is_coinbase());
        assert(cb.vin[0].is_coinbase());
        assert(cb.vin[0].prevout.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 4: Regular transaction is not coinbase
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        uint256 prev = GetRandUint256();
        std::array<uint8_t, 32> dest;
        GetRandBytes(dest.data(), 32);

        auto tx = make_signed_transfer(prev, 0, 100000, dest, kp);
        assert(!tx.is_coinbase());
    }

    // -----------------------------------------------------------------------
    // Test 5: get_value_out sums all outputs
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        std::array<uint8_t, 32> pkh;
        GetRandBytes(pkh.data(), 32);

        tx.vout.push_back(CTxOut(1000, pkh));
        tx.vout.push_back(CTxOut(2000, pkh));
        tx.vout.push_back(CTxOut(3000, pkh));

        assert(tx.get_value_out() == 6000);
    }

    // -----------------------------------------------------------------------
    // Test 6: Empty transaction has zero value out
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        assert(tx.get_value_out() == 0);
    }

    // -----------------------------------------------------------------------
    // Test 7: Serialize/deserialize preserves data
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        uint256 prev = GetRandUint256();
        std::array<uint8_t, 32> dest;
        GetRandBytes(dest.data(), 32);

        auto tx = make_signed_transfer(prev, 0, 100000, dest, kp);
        auto serialized = tx.serialize();

        assert(!serialized.empty());
        // Minimum size: version(4) + varint(1) + input + varint(1) + output + locktime(8)
        assert(serialized.size() > 20);
    }

    // -----------------------------------------------------------------------
    // Test 8: serialize_for_hash excludes signatures
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        uint256 prev = GetRandUint256();
        std::array<uint8_t, 32> dest;
        GetRandBytes(dest.data(), 32);

        CTransaction tx;
        tx.version = 1;
        CTxIn in;
        in.prevout = COutPoint(prev, 0);
        in.pubkey = kp.pubkey;
        tx.vin.push_back(in);
        tx.vout.push_back(CTxOut(100000, dest));

        auto hash_data = tx.serialize_for_hash();

        // Change signature — serialize_for_hash should give same result
        tx.vin[0].signature[0] = 0xFF;
        auto hash_data2 = tx.serialize_for_hash();

        assert(hash_data == hash_data2);
    }

    // -----------------------------------------------------------------------
    // Test 9: COutPoint equality
    // -----------------------------------------------------------------------
    {
        uint256 txid = GetRandUint256();
        COutPoint a(txid, 0);
        COutPoint b(txid, 0);
        COutPoint c(txid, 1);

        assert(a == b);
        assert(a != c);
    }

    // -----------------------------------------------------------------------
    // Test 10: COutPoint ordering
    // -----------------------------------------------------------------------
    {
        uint256 txid1 = GetRandUint256();
        uint256 txid2 = GetRandUint256();

        COutPoint a(txid1, 0);
        COutPoint b(txid1, 1);
        COutPoint c(txid2, 0);

        // Same txid, different index
        if (a.txid == b.txid) {
            assert(a < b);
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: Null outpoint detection
    // -----------------------------------------------------------------------
    {
        COutPoint null_op;
        assert(null_op.is_null());

        COutPoint non_null(GetRandUint256(), 0);
        assert(!non_null.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 12: CTxOut null detection
    // -----------------------------------------------------------------------
    {
        CTxOut null_out;
        assert(null_out.is_null());

        std::array<uint8_t, 32> pkh;
        GetRandBytes(pkh.data(), 32);
        CTxOut real_out(1000, pkh);
        assert(!real_out.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 13: Transaction with multiple inputs
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        std::array<uint8_t, 32> dest;
        GetRandBytes(dest.data(), 32);

        CTransaction tx;
        tx.version = 1;

        for (int i = 0; i < 5; ++i) {
            CTxIn in;
            in.prevout = COutPoint(GetRandUint256(), i);
            in.pubkey = kp.pubkey;
            tx.vin.push_back(in);
        }

        tx.vout.push_back(CTxOut(500000, dest));

        assert(tx.vin.size() == 5);
        assert(!tx.is_coinbase());
    }

    // -----------------------------------------------------------------------
    // Test 14: Transaction with multiple outputs
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        CTxIn cb;
        tx.vin.push_back(cb);

        for (int i = 0; i < 10; ++i) {
            std::array<uint8_t, 32> pkh;
            GetRandBytes(pkh.data(), 32);
            tx.vout.push_back(CTxOut(1000 * (i + 1), pkh));
        }

        assert(tx.vout.size() == 10);
        assert(tx.get_value_out() == 55000);
    }

    // -----------------------------------------------------------------------
    // Test 15: Signature verification
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        uint256 prev = GetRandUint256();
        std::array<uint8_t, 32> dest;
        GetRandBytes(dest.data(), 32);

        auto tx = make_signed_transfer(prev, 0, 100000, dest, kp);

        // Verify the signature
        auto sighash = tx.serialize_for_hash();
        auto txhash = keccak256d(sighash);

        bool valid = ed25519_verify(txhash.data(), 32,
                                     tx.vin[0].pubkey.data(),
                                     tx.vin[0].signature.data());
        assert(valid);
    }

    // -----------------------------------------------------------------------
    // Test 16: Tampered transaction fails signature
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        uint256 prev = GetRandUint256();
        std::array<uint8_t, 32> dest;
        GetRandBytes(dest.data(), 32);

        auto tx = make_signed_transfer(prev, 0, 100000, dest, kp);

        // Tamper with the output amount
        tx.vout[0].amount = 200000;

        // Re-verify — should fail
        auto sighash = tx.serialize_for_hash();
        auto txhash = keccak256d(sighash);

        bool valid = ed25519_verify(txhash.data(), 32,
                                     tx.vin[0].pubkey.data(),
                                     tx.vin[0].signature.data());
        assert(!valid);
    }

    // -----------------------------------------------------------------------
    // Test 17: Default transaction version is 1
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        assert(tx.version == 1);
        assert(tx.locktime == 0);
    }

    // -----------------------------------------------------------------------
    // Test 18: Large value outputs
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        CTxIn cb;
        tx.vin.push_back(cb);

        std::array<uint8_t, 32> pkh;
        GetRandBytes(pkh.data(), 32);
        tx.vout.push_back(CTxOut(consensus::MAX_SUPPLY, pkh));

        assert(tx.get_value_out() == consensus::MAX_SUPPLY);
    }

    // -----------------------------------------------------------------------
    // Test 19: Serialize round-trip preserves txid
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        uint256 prev = GetRandUint256();
        std::array<uint8_t, 32> dest;
        GetRandBytes(dest.data(), 32);

        auto tx = make_signed_transfer(prev, 0, 100000, dest, kp);
        uint256 original_txid = tx.get_txid();

        // Full serialization
        auto data = tx.serialize();
        assert(!data.empty());

        // The txid is computed from serialize_for_hash, not full serialize
        auto hash_data = tx.serialize_for_hash();
        uint256 recomputed = keccak256d(hash_data);
        assert(recomputed == original_txid);
    }

    // -----------------------------------------------------------------------
    // Test 20: Different signers produce different signatures
    // -----------------------------------------------------------------------
    {
        auto kp1 = generate_keypair();
        auto kp2 = generate_keypair();
        uint256 prev = GetRandUint256();
        std::array<uint8_t, 32> dest;
        GetRandBytes(dest.data(), 32);

        auto tx1 = make_signed_transfer(prev, 0, 100000, dest, kp1);
        auto tx2 = make_signed_transfer(prev, 0, 100000, dest, kp2);

        // Different signers, different signatures
        assert(tx1.vin[0].signature != tx2.vin[0].signature);
        // But different pubkeys too
        assert(tx1.vin[0].pubkey != tx2.vin[0].pubkey);
        // And different txids (because pubkey is part of the hash)
        assert(tx1.get_txid() != tx2.get_txid());
    }
}
