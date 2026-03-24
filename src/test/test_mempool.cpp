// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Mempool tests using a real UTXOSet backed by an in-memory SQLite database.

#include "mempool/mempool.h"
#include "chain/utxo.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/transaction.h"
#include "util/types.h"
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

// Helper: create a coinbase transaction that pays to a pubkey hash
static flow::CTransaction make_coinbase(int64_t amount,
                                         const std::array<uint8_t, 32>& pubkey_hash) {
    flow::CTransaction tx;
    flow::CTxIn cb;
    // Coinbase: null prevout
    tx.vin.push_back(cb);
    tx.vout.push_back(flow::CTxOut(amount, pubkey_hash));
    return tx;
}

// Helper: compute pubkey hash (keccak256 of pubkey, first 32 bytes)
static std::array<uint8_t, 32> compute_pkh(const std::array<uint8_t, 32>& pubkey) {
    auto hash = flow::keccak256(pubkey.data(), 32);
    std::array<uint8_t, 32> pkh;
    std::memcpy(pkh.data(), hash.data(), 32);
    return pkh;
}

// Helper: create and sign a transfer transaction
static flow::CTransaction make_signed_tx(
    const flow::uint256& prev_txid, uint32_t prev_vout,
    int64_t amount,
    const std::array<uint8_t, 32>& recipient_pkh,
    const flow::KeyPair& sender_kp)
{
    flow::CTransaction tx;
    flow::CTxIn in;
    in.prevout = flow::COutPoint(prev_txid, prev_vout);
    std::memcpy(in.pubkey.data(), sender_kp.pubkey.data(), 32);
    // Signature will be filled after computing txid
    tx.vin.push_back(in);
    tx.vout.push_back(flow::CTxOut(amount, recipient_pkh));

    // Compute txid (excludes signatures)
    auto txid = tx.get_txid();

    // Sign the txid with sender's key
    auto sig = flow::ed25519_sign(txid.data(), txid.size(),
                                   sender_kp.privkey.data(),
                                   sender_kp.pubkey.data());
    std::memcpy(tx.vin[0].signature.data(), sig.data(), 64);

    return tx;
}

void test_mempool() {
    // Create a temporary database file for UTXOSet
    std::string db_path = "/tmp/flowcoin_test_mempool_utxo.db";
    // Remove any leftover from previous run
    unlink(db_path.c_str());

    {
        // Create UTXO set and mempool
        flow::UTXOSet utxo(db_path);
        flow::Mempool mempool(utxo);

        // Initially empty
        assert(mempool.size() == 0);
        assert(mempool.total_bytes() == 0);

        // Generate two keypairs
        auto kp_alice = flow::generate_keypair();
        auto kp_bob = flow::generate_keypair();
        auto pkh_alice = compute_pkh(kp_alice.pubkey);
        auto pkh_bob = compute_pkh(kp_bob.pubkey);

        // Create a coinbase that pays Alice 50 FLOW
        auto coinbase = make_coinbase(50 * flow::COIN, pkh_alice);
        auto coinbase_txid = coinbase.get_txid();

        // Add the coinbase output to the UTXO set (simulating block acceptance)
        flow::UTXOEntry utxo_entry;
        utxo_entry.value = 50 * flow::COIN;
        utxo_entry.pubkey_hash = pkh_alice;
        utxo_entry.height = 100;  // past maturity
        utxo_entry.is_coinbase = true;
        utxo.add(coinbase_txid, 0, utxo_entry);

        // Verify UTXO was added
        assert(utxo.exists(coinbase_txid, 0));

        // Create a transaction: Alice sends 10 FLOW to Bob
        auto tx1 = make_signed_tx(coinbase_txid, 0,
                                   10 * flow::COIN, pkh_bob, kp_alice);
        // Add change output back to Alice
        tx1.vout.push_back(flow::CTxOut(39 * flow::COIN, pkh_alice));
        // Re-sign because we added an output (changes txid)
        auto txid1 = tx1.get_txid();
        auto sig1 = flow::ed25519_sign(txid1.data(), txid1.size(),
                                        kp_alice.privkey.data(),
                                        kp_alice.pubkey.data());
        std::memcpy(tx1.vin[0].signature.data(), sig1.data(), 64);

        // Add to mempool
        auto result1 = mempool.add_transaction(tx1);
        assert(result1.accepted);
        assert(mempool.size() == 1);

        // Should be able to look up the transaction
        auto tx1_txid = tx1.get_txid();
        assert(mempool.exists(tx1_txid));

        flow::CTransaction retrieved;
        assert(mempool.get(tx1_txid, retrieved));
        assert(retrieved.get_txid() == tx1_txid);

        // Should not be able to add the same transaction again (duplicate)
        auto result_dup = mempool.add_transaction(tx1);
        assert(!result_dup.accepted);
        assert(mempool.size() == 1);

        // Double-spend: try to spend the same UTXO again
        auto tx_double = make_signed_tx(coinbase_txid, 0,
                                         5 * flow::COIN, pkh_bob, kp_alice);
        auto result_double = mempool.add_transaction(tx_double);
        assert(!result_double.accepted);

        // The outpoint should be marked as spent by mempool
        assert(mempool.is_spent_by_mempool(coinbase_txid, 0));

        // Coinbase transactions should be rejected
        auto cb_tx = make_coinbase(50 * flow::COIN, pkh_alice);
        auto result_cb = mempool.add_transaction(cb_tx);
        assert(!result_cb.accepted);

        // Remove the transaction
        mempool.remove(tx1_txid);
        assert(mempool.size() == 0);
        assert(!mempool.exists(tx1_txid));

        // After removal, the outpoint should no longer be spent by mempool
        assert(!mempool.is_spent_by_mempool(coinbase_txid, 0));

        // Get txids from empty mempool
        auto txids = mempool.get_txids();
        assert(txids.empty());

        // Re-add and test clear
        auto result_re = mempool.add_transaction(tx1);
        assert(result_re.accepted);
        assert(mempool.size() == 1);

        mempool.clear();
        assert(mempool.size() == 0);

        // Test remove_for_block
        auto result_block = mempool.add_transaction(tx1);
        assert(result_block.accepted);

        std::vector<flow::CTransaction> block_txs = {tx1};
        mempool.remove_for_block(block_txs);
        assert(mempool.size() == 0);
    }

    // Clean up
    unlink(db_path.c_str());
    // Also remove WAL and SHM files
    unlink((db_path + "-wal").c_str());
    unlink((db_path + "-shm").c_str());
}
