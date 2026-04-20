// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "primitives/transaction.h"
#include "hash/keccak.h"
#include "util/types.h"
#include <cassert>
#include <cstring>
#include <stdexcept>

void test_transaction() {
    // Default transaction
    flow::CTransaction tx;
    assert(tx.version == 1);
    assert(tx.locktime == 0);
    assert(tx.vin.empty());
    assert(tx.vout.empty());

    // Coinbase transaction: single null input
    flow::CTransaction coinbase;
    flow::CTxIn cb_in;
    // Default COutPoint has null txid and index 0 -> is_null()
    assert(cb_in.prevout.is_null());
    assert(cb_in.is_coinbase());
    coinbase.vin.push_back(cb_in);
    coinbase.vout.push_back(flow::CTxOut(50 * flow::COIN, {}));
    assert(coinbase.is_coinbase());
    assert(coinbase.get_value_out() == 50 * flow::COIN);

    // Txid should be deterministic
    auto txid1 = coinbase.get_txid();
    auto txid2 = coinbase.get_txid();
    assert(txid1 == txid2);
    assert(!txid1.is_null());

    // Txid should be keccak256d of serialize_for_hash
    auto hash_data = coinbase.serialize_for_hash();
    auto expected = flow::keccak256d(hash_data.data(), hash_data.size());
    assert(txid1 == expected);

    // serialize_for_hash excludes signatures
    auto ser_hash = coinbase.serialize_for_hash();
    auto ser_full = coinbase.serialize();
    // Full serialization includes the 64-byte signature per input
    // For coinbase with 1 input: full has 64 extra bytes for the signature
    assert(ser_full.size() == ser_hash.size() + 64);

    // Non-coinbase transaction
    flow::CTransaction tx2;
    flow::uint256 prev_txid;
    prev_txid[0] = 0x42;
    flow::CTxIn in2(flow::COutPoint(prev_txid, 0), {}, {});
    tx2.vin.push_back(in2);
    assert(!tx2.is_coinbase());
    assert(!tx2.vin[0].is_coinbase());

    // Multiple outputs
    std::array<uint8_t, 32> pkh1{}, pkh2{};
    pkh1.fill(0xAA);
    pkh2.fill(0xBB);
    tx2.vout.push_back(flow::CTxOut(10 * flow::COIN, pkh1));
    tx2.vout.push_back(flow::CTxOut(5 * flow::COIN, pkh2));
    assert(tx2.get_value_out() == 15 * flow::COIN);

    // Different transactions should have different txids
    assert(coinbase.get_txid() != tx2.get_txid());

    // COutPoint comparison
    flow::COutPoint op1(prev_txid, 0);
    flow::COutPoint op2(prev_txid, 1);
    assert(op1 != op2);
    assert(op1 < op2);

    flow::COutPoint op3(prev_txid, 0);
    assert(op1 == op3);

    // CTxOut: null when amount is 0
    flow::CTxOut null_out;
    assert(null_out.is_null());

    flow::CTxOut real_out(1, {});
    assert(!real_out.is_null());

    // Locktime
    flow::CTransaction tx3;
    tx3.locktime = 500000;
    flow::CTxIn in3;
    tx3.vin.push_back(in3);
    tx3.vout.push_back(flow::CTxOut(1, {}));

    // Locktime should affect the txid
    flow::CTransaction tx4;
    tx4.locktime = 0;
    tx4.vin.push_back(in3);
    tx4.vout.push_back(flow::CTxOut(1, {}));
    assert(tx3.get_txid() != tx4.get_txid());

    // Version should affect the txid
    flow::CTransaction tx5;
    tx5.version = 2;
    tx5.vin.push_back(in3);
    tx5.vout.push_back(flow::CTxOut(1, {}));
    assert(tx4.get_txid() != tx5.get_txid());
}
