// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for transaction policy enforcement: standard tx checks, dust output
// rejection, size limits, fee minimums, version checks, and sigops limits.

#include "primitives/transaction.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "util/random.h"
#include "util/types.h"
#include "consensus/params.h"

#include <cassert>
#include <cstring>
#include <vector>

using namespace flow;

// Helper: compute pubkey hash
static std::array<uint8_t, 32> make_pkh_policy(const std::array<uint8_t, 32>& pubkey) {
    auto h = keccak256(pubkey.data(), 32);
    std::array<uint8_t, 32> result;
    std::memcpy(result.data(), h.data(), 32);
    return result;
}

// Helper: create a basic valid transaction
static CTransaction make_basic_tx() {
    auto kp = generate_keypair();
    auto pkh = make_pkh_policy(kp.pubkey);

    CTransaction tx;
    tx.version = 1;

    CTxIn in;
    uint256 prev_txid = GetRandUint256();
    in.prevout = COutPoint(prev_txid, 0);
    std::memcpy(in.pubkey.data(), kp.pubkey.data(), 32);
    tx.vin.push_back(in);

    auto kp_dest = generate_keypair();
    auto pkh_dest = make_pkh_policy(kp_dest.pubkey);
    tx.vout.push_back(CTxOut(10 * COIN, pkh_dest));

    return tx;
}

void test_policy() {
    // -----------------------------------------------------------------------
    // Test 1: Standard transaction accepted by check_transaction()
    // -----------------------------------------------------------------------
    {
        auto tx = make_basic_tx();
        assert(tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 2: Transaction with no inputs rejected
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        auto kp = generate_keypair();
        tx.vout.push_back(CTxOut(10 * COIN, make_pkh_policy(kp.pubkey)));
        assert(!tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 3: Transaction with no outputs rejected
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 0);
        tx.vin.push_back(in);
        assert(!tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 4: Dust output detected
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        auto pkh = make_pkh_policy(kp.pubkey);

        // Below DUST_THRESHOLD (546)
        CTxOut dust_out(100, pkh);
        assert(dust_out.is_dust());

        CTxOut dust_out2(545, pkh);
        assert(dust_out2.is_dust());

        // At threshold - not dust
        CTxOut ok_out(546, pkh);
        assert(!ok_out.is_dust());

        // Above threshold
        CTxOut big_out(1000, pkh);
        assert(!big_out.is_dust());

        // Zero amount is not dust (it's null)
        CTxOut zero_out(0, pkh);
        assert(!zero_out.is_dust());
    }

    // -----------------------------------------------------------------------
    // Test 5: Negative output amount rejected
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 0);
        tx.vin.push_back(in);

        auto kp = generate_keypair();
        tx.vout.push_back(CTxOut(-1, make_pkh_policy(kp.pubkey)));
        assert(!tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 6: Output exceeding MAX_MONEY rejected
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 0);
        tx.vin.push_back(in);

        auto kp = generate_keypair();
        tx.vout.push_back(CTxOut(MAX_MONEY + 1, make_pkh_policy(kp.pubkey)));
        assert(!tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 7: MAX_MONEY output accepted
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 0);
        tx.vin.push_back(in);

        auto kp = generate_keypair();
        tx.vout.push_back(CTxOut(MAX_MONEY, make_pkh_policy(kp.pubkey)));
        assert(tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 8: Total output value overflow rejected
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 0);
        tx.vin.push_back(in);

        auto kp = generate_keypair();
        auto pkh = make_pkh_policy(kp.pubkey);
        // Two outputs that individually are fine but together exceed MAX_MONEY
        tx.vout.push_back(CTxOut(MAX_MONEY, pkh));
        tx.vout.push_back(CTxOut(1, pkh));
        assert(!tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 9: Duplicate inputs rejected
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;

        uint256 prev = GetRandUint256();
        CTxIn in;
        in.prevout = COutPoint(prev, 0);
        tx.vin.push_back(in);
        tx.vin.push_back(in);  // duplicate

        auto kp = generate_keypair();
        tx.vout.push_back(CTxOut(10 * COIN, make_pkh_policy(kp.pubkey)));
        assert(!tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 10: Coinbase transaction identification
    // -----------------------------------------------------------------------
    {
        CTransaction cb;
        cb.version = 1;
        CTxIn cb_in;
        cb.vin.push_back(cb_in);  // null prevout = coinbase
        auto kp = generate_keypair();
        cb.vout.push_back(CTxOut(50 * COIN, make_pkh_policy(kp.pubkey)));
        assert(cb.is_coinbase());

        // Non-coinbase
        CTransaction regular;
        regular.version = 1;
        CTxIn reg_in;
        uint256 prev = GetRandUint256();
        reg_in.prevout = COutPoint(prev, 0);
        regular.vin.push_back(reg_in);
        regular.vout.push_back(CTxOut(10 * COIN, make_pkh_policy(kp.pubkey)));
        assert(!regular.is_coinbase());
    }

    // -----------------------------------------------------------------------
    // Test 11: is_final for various locktime values
    // -----------------------------------------------------------------------
    {
        CTransaction tx = make_basic_tx();

        // locktime = 0 → always final
        tx.locktime = 0;
        assert(tx.is_final(0, 0));
        assert(tx.is_final(100, 1700000000));

        // locktime < 500000000 → interpreted as block height
        tx.locktime = 100;
        assert(tx.is_final(101, 0));   // height > locktime → final
        assert(!tx.is_final(99, 0));   // height < locktime → not final
        assert(tx.is_final(100, 0));   // height == locktime → final (>=)

        // locktime >= 500000000 → interpreted as timestamp
        tx.locktime = 1700000000;
        assert(tx.is_final(0, 1700000001));  // time > locktime → final
        assert(!tx.is_final(0, 1699999999)); // time < locktime → not final
    }

    // -----------------------------------------------------------------------
    // Test 12: Transaction serialized size calculation
    // -----------------------------------------------------------------------
    {
        auto tx = make_basic_tx();
        size_t computed = tx.get_serialize_size();
        auto serialized = tx.serialize();
        assert(computed == serialized.size());
    }

    // -----------------------------------------------------------------------
    // Test 13: get_value_out returns total output amounts
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;

        auto kp1 = generate_keypair();
        auto kp2 = generate_keypair();
        tx.vout.push_back(CTxOut(10 * COIN, make_pkh_policy(kp1.pubkey)));
        tx.vout.push_back(CTxOut(20 * COIN, make_pkh_policy(kp2.pubkey)));

        assert(tx.get_value_out() == 30 * COIN);
    }

    // -----------------------------------------------------------------------
    // Test 14: Transaction serialize/deserialize round-trip
    // -----------------------------------------------------------------------
    {
        auto tx = make_basic_tx();
        auto serialized = tx.serialize();

        CTransaction deserialized;
        assert(deserialized.deserialize(serialized));

        assert(deserialized.version == tx.version);
        assert(deserialized.vin.size() == tx.vin.size());
        assert(deserialized.vout.size() == tx.vout.size());
        assert(deserialized.get_txid() == tx.get_txid());
    }

    // -----------------------------------------------------------------------
    // Test 15: get_virtual_size equals serialized size
    // -----------------------------------------------------------------------
    {
        auto tx = make_basic_tx();
        assert(tx.get_virtual_size() == tx.get_serialize_size());
    }

    // -----------------------------------------------------------------------
    // Test 16: Minimum fee rate from consensus params
    // -----------------------------------------------------------------------
    {
        assert(consensus::MIN_RELAY_FEE == 1000);
    }

    // -----------------------------------------------------------------------
    // Test 17: DUST_THRESHOLD value
    // -----------------------------------------------------------------------
    {
        assert(DUST_THRESHOLD == 546);
    }

    // -----------------------------------------------------------------------
    // Test 18: MAX_TX_SIZE limit
    // -----------------------------------------------------------------------
    {
        assert(MAX_TX_SIZE == 1'000'000);
    }

    // -----------------------------------------------------------------------
    // Test 19: Multiple valid outputs pass check
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;
        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 0);
        tx.vin.push_back(in);

        auto kp = generate_keypair();
        auto pkh = make_pkh_policy(kp.pubkey);
        for (int i = 0; i < 10; ++i) {
            tx.vout.push_back(CTxOut(1 * COIN, pkh));
        }
        assert(tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 20: Transaction equality based on txid
    // -----------------------------------------------------------------------
    {
        auto tx1 = make_basic_tx();
        auto tx2 = tx1;  // copy
        assert(tx1 == tx2);

        // Different tx
        auto tx3 = make_basic_tx();
        assert(tx1 != tx3);
    }

    // -----------------------------------------------------------------------
    // Test 21: Coinbase maturity parameter
    // -----------------------------------------------------------------------
    {
        assert(consensus::COINBASE_MATURITY == 100);
    }

    // -----------------------------------------------------------------------
    // Test 22: MAX_BLOCK_SIGOPS
    // -----------------------------------------------------------------------
    {
        assert(consensus::MAX_BLOCK_SIGOPS == 80000);
    }

    // -----------------------------------------------------------------------
    // Test 23: MAX_BLOCK_SIZE
    // -----------------------------------------------------------------------
    {
        assert(consensus::MAX_BLOCK_SIZE == 32'000'000);
    }

    // -----------------------------------------------------------------------
    // Test 24: HALVING_INTERVAL
    // -----------------------------------------------------------------------
    {
        assert(consensus::HALVING_INTERVAL == 210000);
    }

    // -----------------------------------------------------------------------
    // Test 25: Transaction with many inputs passes basic checks
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;

        for (int i = 0; i < 50; ++i) {
            CTxIn in;
            uint256 prev;
            GetRandBytes(prev.data(), 32);
            in.prevout = COutPoint(prev, static_cast<uint32_t>(i));
            tx.vin.push_back(in);
        }

        auto kp = generate_keypair();
        tx.vout.push_back(CTxOut(100 * COIN, make_pkh_policy(kp.pubkey)));
        assert(tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 26: Transaction with many outputs passes basic checks
    // -----------------------------------------------------------------------
    {
        CTransaction tx;
        tx.version = 1;

        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 0);
        tx.vin.push_back(in);

        auto kp = generate_keypair();
        auto pkh = make_pkh_policy(kp.pubkey);
        for (int i = 0; i < 100; ++i) {
            tx.vout.push_back(CTxOut(1000, pkh));
        }
        assert(tx.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 27: Signature hash computation is deterministic
    // -----------------------------------------------------------------------
    {
        auto tx = make_basic_tx();
        auto sh1 = tx.signature_hash(0);
        auto sh2 = tx.signature_hash(0);
        assert(sh1 == sh2);
        assert(!sh1.is_null());
    }

    // -----------------------------------------------------------------------
    // Test 28: CTxOut::to_string produces output
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        CTxOut out(42 * COIN, make_pkh_policy(kp.pubkey));
        auto s = out.to_string();
        assert(!s.empty());
    }

    // -----------------------------------------------------------------------
    // Test 29: COutPoint::to_string produces output
    // -----------------------------------------------------------------------
    {
        uint256 txid = GetRandUint256();
        COutPoint op(txid, 3);
        auto s = op.to_string();
        assert(!s.empty());
    }

    // -----------------------------------------------------------------------
    // Test 30: CTransaction::to_string produces output
    // -----------------------------------------------------------------------
    {
        auto tx = make_basic_tx();
        auto s = tx.to_string();
        assert(!s.empty());
    }

    // -----------------------------------------------------------------------
    // Test 31: INITIAL_REWARD correct
    // -----------------------------------------------------------------------
    {
        assert(consensus::INITIAL_REWARD == 50LL * consensus::COIN);
    }

    // -----------------------------------------------------------------------
    // Test 32: MAX_SUPPLY correct
    // -----------------------------------------------------------------------
    {
        assert(consensus::MAX_SUPPLY == 21'000'000LL * consensus::COIN);
    }

    // -----------------------------------------------------------------------
    // Test 33: TARGET_BLOCK_TIME correct
    // -----------------------------------------------------------------------
    {
        assert(consensus::TARGET_BLOCK_TIME == 600);
    }

    // -----------------------------------------------------------------------
    // Test 34: RETARGET_INTERVAL correct
    // -----------------------------------------------------------------------
    {
        assert(consensus::RETARGET_INTERVAL == 2016);
        assert(consensus::RETARGET_TIMESPAN == 2016 * 600);
    }

    // -----------------------------------------------------------------------
    // Test 35: Transaction check accepts coinbase
    // -----------------------------------------------------------------------
    {
        CTransaction cb;
        cb.version = 1;
        CTxIn cb_in;
        cb.vin.push_back(cb_in);
        auto kp = generate_keypair();
        cb.vout.push_back(CTxOut(50 * COIN, make_pkh_policy(kp.pubkey)));
        assert(cb.check_transaction());
    }

    // -----------------------------------------------------------------------
    // Test 36: CTxIn get_serialize_size
    // -----------------------------------------------------------------------
    {
        CTxIn in;
        assert(in.get_serialize_size() == 132);  // 36 + 32 + 64
    }

    // -----------------------------------------------------------------------
    // Test 37: CTxOut get_serialize_size
    // -----------------------------------------------------------------------
    {
        auto kp = generate_keypair();
        CTxOut out(COIN, make_pkh_policy(kp.pubkey));
        assert(out.get_serialize_size() == 40);  // 8 + 32
    }

    // -----------------------------------------------------------------------
    // Test 38: CTxIn serialize/deserialize
    // -----------------------------------------------------------------------
    {
        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 7);
        GetRandBytes(in.pubkey.data(), 32);
        GetRandBytes(in.signature.data(), 64);

        auto data = in.serialize();
        assert(data.size() == in.get_serialize_size());
    }

    // -----------------------------------------------------------------------
    // Test 39: CTxIn serialize_for_hash excludes signature
    // -----------------------------------------------------------------------
    {
        CTxIn in;
        uint256 prev = GetRandUint256();
        in.prevout = COutPoint(prev, 0);
        GetRandBytes(in.pubkey.data(), 32);

        auto hash_data1 = in.serialize_for_hash();

        // Change signature
        GetRandBytes(in.signature.data(), 64);
        auto hash_data2 = in.serialize_for_hash();

        // Hash serialization should be the same (sigs excluded)
        assert(hash_data1 == hash_data2);
    }

    // -----------------------------------------------------------------------
    // Test 40: CTxIn is_coinbase
    // -----------------------------------------------------------------------
    {
        CTxIn coinbase_in;
        assert(coinbase_in.is_coinbase());  // null prevout

        CTxIn regular_in;
        uint256 prev = GetRandUint256();
        regular_in.prevout = COutPoint(prev, 0);
        assert(!regular_in.is_coinbase());
    }

    // -----------------------------------------------------------------------
    // Test 41: CTransaction has_witness always false
    // -----------------------------------------------------------------------
    {
        CTransaction tx = make_basic_tx();
        assert(!tx.has_witness());
    }

    // -----------------------------------------------------------------------
    // Test 42: FINALITY_DEPTH
    // -----------------------------------------------------------------------
    {
        assert(consensus::FINALITY_DEPTH == 6);
    }

    // -----------------------------------------------------------------------
    // Test 43: Genesis timestamp
    // -----------------------------------------------------------------------
    {
        assert(consensus::GENESIS_TIMESTAMP == 1742515200);
    }

    // -----------------------------------------------------------------------
    // Test 44: BIP44 coin type
    // -----------------------------------------------------------------------
    {
        assert(consensus::BIP44_COIN_TYPE == 9555);
    }

    // -----------------------------------------------------------------------
    // Test 45: Model growth parameters
    // -----------------------------------------------------------------------
    {
        assert(consensus::GENESIS_D_MODEL == 512);
        assert(consensus::GENESIS_N_LAYERS == 8);
        assert(consensus::GENESIS_D_FF == 1024);
        assert(consensus::GENESIS_N_HEADS == 8);
        assert(consensus::GENESIS_VOCAB == 256);
        assert(consensus::GENESIS_SEQ_LEN == 256);
        assert(consensus::MAX_D_MODEL == 1024);
        assert(consensus::MAX_N_LAYERS == 24);
        assert(consensus::MAX_D_FF == 2048);
    }

    // -----------------------------------------------------------------------
    // Test 46: Growth plateau parameters
    // -----------------------------------------------------------------------
    {
        assert(consensus::GROWTH_PLATEAU_LEN == 100);
        assert(consensus::NUM_GROWTH_PLATEAUS == 5);
        assert(consensus::DIM_GROWTH_END == 500);
    }

    // -----------------------------------------------------------------------
    // Test 47: Pruning parameters
    // -----------------------------------------------------------------------
    {
        assert(consensus::MIN_BLOCKS_TO_KEEP == 288);
        assert(consensus::DEFAULT_PRUNE_TARGET_MB == 550);
    }

    // -----------------------------------------------------------------------
    // Test 48: IBD parameters
    // -----------------------------------------------------------------------
    {
        assert(consensus::IBD_MIN_BLOCKS_BEHIND == 144);
        assert(consensus::MAX_HEADERS_RESULTS == 2000);
        assert(consensus::MAX_BLOCKS_IN_TRANSIT == 16);
    }

    // -----------------------------------------------------------------------
    // Test 49: Mempool limits
    // -----------------------------------------------------------------------
    {
        assert(consensus::MAX_MEMPOOL_SIZE == 300'000'000);
        assert(consensus::MEMPOOL_EXPIRY == 1'209'600);
    }

    // -----------------------------------------------------------------------
    // Test 50: Dimension validation helpers
    // -----------------------------------------------------------------------
    {
        assert(consensus::is_valid_d_model(512));
        assert(consensus::is_valid_d_model(640));
        assert(consensus::is_valid_d_model(768));
        assert(consensus::is_valid_d_model(896));
        assert(consensus::is_valid_d_model(1024));
        assert(!consensus::is_valid_d_model(256));   // too small
        assert(!consensus::is_valid_d_model(2048));  // too large
        assert(!consensus::is_valid_d_model(500));   // not multiple of 64

        assert(consensus::is_valid_n_layers(8));
        assert(consensus::is_valid_n_layers(12));
        assert(consensus::is_valid_n_layers(24));
        assert(!consensus::is_valid_n_layers(4));    // too small
        assert(!consensus::is_valid_n_layers(28));   // too large
        assert(!consensus::is_valid_n_layers(10));   // not multiple of 4

        assert(consensus::compute_d_head(512, 8) == 64);
        assert(consensus::compute_d_head(1024, 16) == 64);
        assert(consensus::compute_d_head(512, 0) == 0);
    }
}
