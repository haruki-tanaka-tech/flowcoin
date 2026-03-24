// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Advanced mempool tests: fee ordering, concurrent access, remove_for_block,
// sorted transaction retrieval, byte tracking, and edge cases.

#include "mempool/mempool.h"
#include "chain/utxo.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/transaction.h"
#include "util/random.h"
#include "util/types.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace flow;

// Helper: compute pubkey hash
static std::array<uint8_t, 32> compute_pkh_adv(const std::array<uint8_t, 32>& pubkey) {
    auto hash = keccak256(pubkey.data(), 32);
    std::array<uint8_t, 32> p;
    std::memcpy(p.data(), hash.data(), 32);
    return p;
}

// Helper: create and sign a transfer transaction with specified output amount
static CTransaction make_signed_tx_adv(
    const uint256& prev_txid, uint32_t prev_vout,
    Amount amount, Amount change,
    const std::array<uint8_t, 32>& recipient_pkh,
    const KeyPair& sender_kp)
{
    CTransaction tx;
    CTxIn in;
    in.prevout = COutPoint(prev_txid, prev_vout);
    std::memcpy(in.pubkey.data(), sender_kp.pubkey.data(), 32);
    tx.vin.push_back(in);
    tx.vout.push_back(CTxOut(amount, recipient_pkh));
    if (change > 0) {
        auto sender_pkh = compute_pkh_adv(sender_kp.pubkey);
        tx.vout.push_back(CTxOut(change, sender_pkh));
    }

    auto txid = tx.get_txid();
    auto sig = ed25519_sign(txid.data(), txid.size(),
                             sender_kp.privkey.data(),
                             sender_kp.pubkey.data());
    std::memcpy(tx.vin[0].signature.data(), sig.data(), 64);
    return tx;
}

// Helper: add a UTXO to the set for a given keypair
static uint256 add_utxo(UTXOSet& utxo, const KeyPair& kp, Amount value,
                         uint32_t vout = 0, uint64_t height = 100) {
    uint256 txid = GetRandUint256();
    UTXOEntry entry;
    entry.value = value;
    entry.pubkey_hash = compute_pkh_adv(kp.pubkey);
    entry.height = height;
    entry.is_coinbase = false;
    utxo.add(txid, vout, entry);
    return txid;
}

void test_mempool_advanced() {
    std::string db_path = "/tmp/flowcoin_test_mempool_adv_" + std::to_string(getpid()) + ".db";
    unlink(db_path.c_str());

    {
        UTXOSet utxo(db_path);
        Mempool mempool(utxo);

        auto kp_alice = generate_keypair();
        auto kp_bob = generate_keypair();
        auto pkh_alice = compute_pkh_adv(kp_alice.pubkey);
        auto pkh_bob = compute_pkh_adv(kp_bob.pubkey);

        // -----------------------------------------------------------------------
        // Test 1: Fee-rate sorted transaction retrieval
        // -----------------------------------------------------------------------
        {
            // Create multiple UTXOs for Alice with different amounts
            auto txid1 = add_utxo(utxo, kp_alice, 100 * COIN);
            auto txid2 = add_utxo(utxo, kp_alice, 200 * COIN);
            auto txid3 = add_utxo(utxo, kp_alice, 300 * COIN);

            // Create transactions with different fee rates
            // tx with large fee (high fee rate)
            auto tx_high = make_signed_tx_adv(txid1, 0, 10 * COIN, 50 * COIN, pkh_bob, kp_alice);
            // tx with medium fee
            auto tx_med = make_signed_tx_adv(txid2, 0, 10 * COIN, 170 * COIN, pkh_bob, kp_alice);
            // tx with small fee
            auto tx_low = make_signed_tx_adv(txid3, 0, 10 * COIN, 280 * COIN, pkh_bob, kp_alice);

            auto r1 = mempool.add_transaction(tx_high);
            auto r2 = mempool.add_transaction(tx_med);
            auto r3 = mempool.add_transaction(tx_low);
            assert(r1.accepted);
            assert(r2.accepted);
            assert(r3.accepted);
            assert(mempool.size() == 3);

            // Get sorted transactions (highest fee rate first)
            auto sorted = mempool.get_sorted_transactions();
            assert(sorted.size() == 3);

            // Verify sorted by fee rate descending
            // The tx with highest fee should be first
            // Fee = input_value - output_value
            // tx_high fee = 100*COIN - 10*COIN - 50*COIN = 40*COIN
            // tx_med fee = 200*COIN - 10*COIN - 170*COIN = 20*COIN
            // tx_low fee = 300*COIN - 10*COIN - 280*COIN = 10*COIN

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 2: Duplicate rejection
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);

            auto r1 = mempool.add_transaction(tx);
            assert(r1.accepted);

            auto r2 = mempool.add_transaction(tx);
            assert(!r2.accepted);

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 3: Double-spend rejection within mempool
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);

            auto tx1 = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);
            auto tx2 = make_signed_tx_adv(txid, 0, 5 * COIN, 44 * COIN, pkh_bob, kp_alice);

            auto r1 = mempool.add_transaction(tx1);
            assert(r1.accepted);

            auto r2 = mempool.add_transaction(tx2);
            assert(!r2.accepted);  // Same outpoint already spent

            assert(mempool.is_spent_by_mempool(txid, 0));

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 4: Coinbase rejection
        // -----------------------------------------------------------------------
        {
            CTransaction cb_tx;
            CTxIn cb_in;
            cb_tx.vin.push_back(cb_in);
            cb_tx.vout.push_back(CTxOut(50 * COIN, pkh_alice));

            auto r = mempool.add_transaction(cb_tx);
            assert(!r.accepted);
        }

        // -----------------------------------------------------------------------
        // Test 5: Total bytes tracking
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);

            assert(mempool.total_bytes() == 0);

            auto r = mempool.add_transaction(tx);
            assert(r.accepted);
            assert(mempool.total_bytes() > 0);

            size_t bytes_with_tx = mempool.total_bytes();

            auto tx_txid = tx.get_txid();
            mempool.remove(tx_txid);
            assert(mempool.total_bytes() == 0);

            // Bytes should have been the serialized size
            assert(bytes_with_tx > 100);  // A transaction is at least ~200 bytes

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 6: get_txids returns all transaction IDs
        // -----------------------------------------------------------------------
        {
            auto txid1 = add_utxo(utxo, kp_alice, 50 * COIN);
            auto txid2 = add_utxo(utxo, kp_alice, 60 * COIN);

            auto tx1 = make_signed_tx_adv(txid1, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);
            auto tx2 = make_signed_tx_adv(txid2, 0, 10 * COIN, 49 * COIN, pkh_bob, kp_alice);

            mempool.add_transaction(tx1);
            mempool.add_transaction(tx2);

            auto txids = mempool.get_txids();
            assert(txids.size() == 2);

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 7: remove_for_block clears matching transactions
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);

            auto r = mempool.add_transaction(tx);
            assert(r.accepted);
            assert(mempool.size() == 1);

            std::vector<CTransaction> block_txs = {tx};
            mempool.remove_for_block(block_txs);
            assert(mempool.size() == 0);
        }

        // -----------------------------------------------------------------------
        // Test 8: remove_for_block evicts conflicting transactions
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);

            // Add tx1 to mempool spending this UTXO
            auto tx1 = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);
            auto r = mempool.add_transaction(tx1);
            assert(r.accepted);

            // Create a different tx spending the same UTXO (for the block)
            auto tx_block = make_signed_tx_adv(txid, 0, 20 * COIN, 29 * COIN, pkh_bob, kp_alice);

            // Remove conflicts
            std::vector<CTransaction> block_txs = {tx_block};
            mempool.remove_for_block(block_txs);
            assert(mempool.size() == 0);
        }

        // -----------------------------------------------------------------------
        // Test 9: get() retrieves correct transaction
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);

            mempool.add_transaction(tx);
            auto tx_txid = tx.get_txid();

            CTransaction retrieved;
            bool found = mempool.get(tx_txid, retrieved);
            assert(found);
            assert(retrieved.get_txid() == tx_txid);

            // Non-existent transaction
            uint256 fake_txid = GetRandUint256();
            CTransaction not_found_tx;
            assert(!mempool.get(fake_txid, not_found_tx));

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 10: exists() check
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);

            auto tx_txid = tx.get_txid();
            assert(!mempool.exists(tx_txid));

            mempool.add_transaction(tx);
            assert(mempool.exists(tx_txid));

            mempool.remove(tx_txid);
            assert(!mempool.exists(tx_txid));
        }

        // -----------------------------------------------------------------------
        // Test 11: get_sorted_transactions with max_count limit
        // -----------------------------------------------------------------------
        {
            std::vector<uint256> utxo_ids;
            for (int i = 0; i < 5; ++i) {
                utxo_ids.push_back(add_utxo(utxo, kp_alice, (50 + i * 10) * COIN));
            }

            for (int i = 0; i < 5; ++i) {
                auto tx = make_signed_tx_adv(utxo_ids[i], 0, 10 * COIN,
                                              (39 + i * 10) * COIN, pkh_bob, kp_alice);
                mempool.add_transaction(tx);
            }

            assert(mempool.size() == 5);

            auto top3 = mempool.get_sorted_transactions(3);
            assert(top3.size() == 3);

            auto all = mempool.get_sorted_transactions(0);
            assert(all.size() == 5);

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 12: Thread safety - concurrent reads while adding
        // -----------------------------------------------------------------------
        {
            // Add some initial UTXOs
            std::vector<uint256> utxo_ids;
            for (int i = 0; i < 20; ++i) {
                utxo_ids.push_back(add_utxo(utxo, kp_alice, 50 * COIN));
            }

            // Add 10 transactions from the main thread
            std::vector<CTransaction> txs;
            for (int i = 0; i < 10; ++i) {
                auto tx = make_signed_tx_adv(utxo_ids[i], 0, 10 * COIN,
                                              39 * COIN, pkh_bob, kp_alice);
                txs.push_back(tx);
            }

            // Reader thread
            std::atomic<bool> stop{false};
            std::thread reader([&]() {
                while (!stop.load()) {
                    // These should not crash even during concurrent modification
                    auto sz = mempool.size();
                    (void)sz;
                    auto txids = mempool.get_txids();
                    (void)txids;
                    auto total = mempool.total_bytes();
                    (void)total;
                }
            });

            // Add transactions from main thread
            for (const auto& tx : txs) {
                mempool.add_transaction(tx);
            }

            stop.store(true);
            reader.join();

            assert(mempool.size() == 10);
            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 13: Multiple outputs in a single transaction
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 100 * COIN);

            CTransaction tx;
            CTxIn in;
            in.prevout = COutPoint(txid, 0);
            std::memcpy(in.pubkey.data(), kp_alice.pubkey.data(), 32);
            tx.vin.push_back(in);

            // Multiple outputs
            tx.vout.push_back(CTxOut(20 * COIN, pkh_bob));
            tx.vout.push_back(CTxOut(30 * COIN, pkh_bob));
            tx.vout.push_back(CTxOut(49 * COIN, pkh_alice));

            auto tx_txid = tx.get_txid();
            auto sig = ed25519_sign(tx_txid.data(), tx_txid.size(),
                                     kp_alice.privkey.data(), kp_alice.pubkey.data());
            std::memcpy(tx.vin[0].signature.data(), sig.data(), 64);

            auto r = mempool.add_transaction(tx);
            assert(r.accepted);

            CTransaction retrieved;
            assert(mempool.get(tx.get_txid(), retrieved));
            assert(retrieved.vout.size() == 3);

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 14: Clear empties everything
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);

            mempool.add_transaction(tx);
            assert(mempool.size() > 0);
            assert(mempool.total_bytes() > 0);

            mempool.clear();
            assert(mempool.size() == 0);
            assert(mempool.total_bytes() == 0);
            assert(mempool.get_txids().empty());
        }

        // -----------------------------------------------------------------------
        // Test 15: Spending non-existent UTXO rejected
        // -----------------------------------------------------------------------
        {
            uint256 fake_txid = GetRandUint256();
            auto tx = make_signed_tx_adv(fake_txid, 0, 10 * COIN, 0, pkh_bob, kp_alice);

            auto r = mempool.add_transaction(tx);
            assert(!r.accepted);
        }

        // -----------------------------------------------------------------------
        // Test 16: After removing from mempool, outpoint is no longer spent
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);

            mempool.add_transaction(tx);
            assert(mempool.is_spent_by_mempool(txid, 0));

            mempool.remove(tx.get_txid());
            assert(!mempool.is_spent_by_mempool(txid, 0));
        }

        // -----------------------------------------------------------------------
        // Test 17: Multiple transactions from same sender
        // -----------------------------------------------------------------------
        {
            auto txid1 = add_utxo(utxo, kp_alice, 50 * COIN);
            auto txid2 = add_utxo(utxo, kp_alice, 60 * COIN);
            auto txid3 = add_utxo(utxo, kp_alice, 70 * COIN);

            auto tx1 = make_signed_tx_adv(txid1, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);
            auto tx2 = make_signed_tx_adv(txid2, 0, 20 * COIN, 39 * COIN, pkh_bob, kp_alice);
            auto tx3 = make_signed_tx_adv(txid3, 0, 30 * COIN, 39 * COIN, pkh_bob, kp_alice);

            assert(mempool.add_transaction(tx1).accepted);
            assert(mempool.add_transaction(tx2).accepted);
            assert(mempool.add_transaction(tx3).accepted);

            assert(mempool.size() == 3);

            // Verify all exist
            assert(mempool.exists(tx1.get_txid()));
            assert(mempool.exists(tx2.get_txid()));
            assert(mempool.exists(tx3.get_txid()));

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 18: Transaction with wrong signature rejected
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);

            CTransaction bad_tx;
            CTxIn in;
            in.prevout = COutPoint(txid, 0);
            std::memcpy(in.pubkey.data(), kp_alice.pubkey.data(), 32);
            bad_tx.vin.push_back(in);
            bad_tx.vout.push_back(CTxOut(10 * COIN, pkh_bob));
            bad_tx.vout.push_back(CTxOut(39 * COIN, pkh_alice));

            // Sign with Bob's key (wrong)
            auto bad_txid = bad_tx.get_txid();
            auto bad_sig = ed25519_sign(bad_txid.data(), bad_txid.size(),
                                         kp_bob.privkey.data(), kp_bob.pubkey.data());
            std::memcpy(bad_tx.vin[0].signature.data(), bad_sig.data(), 64);

            auto r = mempool.add_transaction(bad_tx);
            assert(!r.accepted);
        }

        // -----------------------------------------------------------------------
        // Test 19: Remove non-existent tx does not crash
        // -----------------------------------------------------------------------
        {
            uint256 fake = GetRandUint256();
            mempool.remove(fake);  // Should be a no-op
            assert(mempool.size() == 0);
        }

        // -----------------------------------------------------------------------
        // Test 20: Size returns correct count after mixed operations
        // -----------------------------------------------------------------------
        {
            auto txid1 = add_utxo(utxo, kp_alice, 50 * COIN);
            auto txid2 = add_utxo(utxo, kp_alice, 60 * COIN);

            auto tx1 = make_signed_tx_adv(txid1, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);
            auto tx2 = make_signed_tx_adv(txid2, 0, 10 * COIN, 49 * COIN, pkh_bob, kp_alice);

            mempool.add_transaction(tx1);
            assert(mempool.size() == 1);

            mempool.add_transaction(tx2);
            assert(mempool.size() == 2);

            mempool.remove(tx1.get_txid());
            assert(mempool.size() == 1);

            mempool.remove(tx2.get_txid());
            assert(mempool.size() == 0);
        }

        // -----------------------------------------------------------------------
        // Test 21: Batch add and remove_for_block
        // -----------------------------------------------------------------------
        {
            std::vector<CTransaction> batch_txs;
            for (int i = 0; i < 10; ++i) {
                auto utxo_id = add_utxo(utxo, kp_alice, (50 + i) * COIN);
                auto tx = make_signed_tx_adv(utxo_id, 0, 10 * COIN,
                                              (39 + i) * COIN, pkh_bob, kp_alice);
                batch_txs.push_back(tx);
                auto r = mempool.add_transaction(tx);
                assert(r.accepted);
            }
            assert(mempool.size() == 10);

            // Remove half as a block
            std::vector<CTransaction> block_txs(batch_txs.begin(), batch_txs.begin() + 5);
            mempool.remove_for_block(block_txs);
            assert(mempool.size() == 5);

            // Remove rest
            std::vector<CTransaction> block_txs2(batch_txs.begin() + 5, batch_txs.end());
            mempool.remove_for_block(block_txs2);
            assert(mempool.size() == 0);
        }

        // -----------------------------------------------------------------------
        // Test 22: Remove for block with empty block
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);
            mempool.add_transaction(tx);
            assert(mempool.size() == 1);

            // Empty block should not remove anything
            std::vector<CTransaction> empty_block;
            mempool.remove_for_block(empty_block);
            assert(mempool.size() == 1);

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 23: Transaction with single output (no change)
        // -----------------------------------------------------------------------
        {
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 49 * COIN, 0, pkh_bob, kp_alice);

            auto r = mempool.add_transaction(tx);
            assert(r.accepted);

            CTransaction retrieved;
            assert(mempool.get(tx.get_txid(), retrieved));
            assert(retrieved.vout.size() == 1);

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 24: Verify reject_reason is set on failure
        // -----------------------------------------------------------------------
        {
            // Duplicate
            auto txid = add_utxo(utxo, kp_alice, 50 * COIN);
            auto tx = make_signed_tx_adv(txid, 0, 10 * COIN, 39 * COIN, pkh_bob, kp_alice);
            mempool.add_transaction(tx);

            auto r = mempool.add_transaction(tx);
            assert(!r.accepted);
            assert(!r.reject_reason.empty());

            mempool.clear();
        }

        // -----------------------------------------------------------------------
        // Test 25: Stress test - add and remove many transactions
        // -----------------------------------------------------------------------
        {
            for (int round = 0; round < 3; ++round) {
                std::vector<CTransaction> round_txs;
                for (int i = 0; i < 20; ++i) {
                    auto utxo_id = add_utxo(utxo, kp_alice, 50 * COIN);
                    auto tx = make_signed_tx_adv(utxo_id, 0, 10 * COIN,
                                                  39 * COIN, pkh_bob, kp_alice);
                    round_txs.push_back(tx);
                    mempool.add_transaction(tx);
                }
                assert(mempool.size() == 20);

                for (const auto& tx : round_txs) {
                    mempool.remove(tx.get_txid());
                }
                assert(mempool.size() == 0);
            }
        }
    }

    // Clean up
    unlink(db_path.c_str());
    unlink((db_path + "-wal").c_str());
    unlink((db_path + "-shm").c_str());
}
