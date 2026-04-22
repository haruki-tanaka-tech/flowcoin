// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for TxIndex-like functionality via the UTXO set.
// Verifies that transactions can be indexed by block, looked up by txid,
// and deindexed cleanly when a block is disconnected.
//
// Since FlowCoin uses a UTXO model (not a full tx index), we test the
// UTXO set's ability to track transaction outputs and remove them.

#include "chain/utxo.h"
#include "crypto/keys.h"
#include "hash/keccak.h"
#include "primitives/transaction.h"
#include "util/types.h"
#include <cassert>
#include <cstring>
#include <unistd.h>
#include <vector>

// Helper: compute pubkey hash
static std::array<uint8_t, 32> compute_pkh(const std::array<uint8_t, 32>& pubkey) {
    auto hash = flow::keccak256(pubkey.data(), 32);
    std::array<uint8_t, 32> pkh;
    std::memcpy(pkh.data(), hash.data(), 32);
    return pkh;
}

// Helper: make a fake txid from an index
static flow::uint256 make_txid(uint32_t index) {
    flow::uint256 txid;
    txid.set_null();
    std::memcpy(txid.data(), &index, sizeof(index));
    return txid;
}

void test_txindex() {
    using namespace flow;

    std::string db_path = "/tmp/flowcoin_test_txindex.db";
    unlink(db_path.c_str());

    {
        UTXOSet utxo(db_path);

        auto kp = generate_keypair();
        auto pkh = compute_pkh(kp.pubkey);

        // Test 1: Index a block's outputs and find them
        {
            auto txid1 = make_txid(1);
            auto txid2 = make_txid(2);

            UTXOEntry entry1;
            entry1.value = 50 * COIN;
            entry1.pubkey_hash = pkh;
            entry1.height = 1;
            entry1.is_coinbase = true;

            UTXOEntry entry2;
            entry2.value = 10 * COIN;
            entry2.pubkey_hash = pkh;
            entry2.height = 1;
            entry2.is_coinbase = false;

            // Add outputs (simulating block connection)
            utxo.begin_transaction();
            assert(utxo.add(txid1, 0, entry1));
            assert(utxo.add(txid2, 0, entry2));
            assert(utxo.add(txid2, 1, entry2));
            utxo.commit_transaction();

            // Find the outputs
            assert(utxo.exists(txid1, 0));
            assert(utxo.exists(txid2, 0));
            assert(utxo.exists(txid2, 1));

            // Verify values
            UTXOEntry found;
            assert(utxo.get(txid1, 0, found));
            assert(found.value == 50 * COIN);
            assert(found.is_coinbase);
            assert(found.height == 1);
            assert(found.pubkey_hash == pkh);

            assert(utxo.get(txid2, 0, found));
            assert(found.value == 10 * COIN);
            assert(!found.is_coinbase);
        }

        // Test 2: Deindex a block (remove all its outputs)
        {
            auto txid1 = make_txid(1);
            auto txid2 = make_txid(2);

            utxo.begin_transaction();
            assert(utxo.remove(txid1, 0));
            assert(utxo.remove(txid2, 0));
            assert(utxo.remove(txid2, 1));
            utxo.commit_transaction();

            // Entries should be gone
            assert(!utxo.exists(txid1, 0));
            assert(!utxo.exists(txid2, 0));
            assert(!utxo.exists(txid2, 1));
        }

        // Test 3: Find returns not-found for unknown txid
        {
            auto unknown_txid = make_txid(9999);
            assert(!utxo.exists(unknown_txid, 0));

            UTXOEntry entry;
            assert(!utxo.get(unknown_txid, 0, entry));
        }

        // Test 4: Remove non-existent entry returns false
        {
            auto unknown_txid = make_txid(8888);
            assert(!utxo.remove(unknown_txid, 0));
        }

        // Test 5: Multiple outputs per transaction
        {
            auto txid = make_txid(100);
            UTXOEntry entry;
            entry.value = 5 * COIN;
            entry.pubkey_hash = pkh;
            entry.height = 10;
            entry.is_coinbase = false;

            // Add 5 outputs
            for (uint32_t i = 0; i < 5; i++) {
                entry.value = (int64_t)(i + 1) * COIN;
                assert(utxo.add(txid, i, entry));
            }

            // Verify each output
            for (uint32_t i = 0; i < 5; i++) {
                UTXOEntry found;
                assert(utxo.get(txid, i, found));
                assert(found.value == (int64_t)(i + 1) * COIN);
            }

            // Output 5 should not exist
            assert(!utxo.exists(txid, 5));

            // Remove in reverse order
            for (uint32_t i = 5; i > 0; i--) {
                assert(utxo.remove(txid, i - 1));
            }

            // All gone
            for (uint32_t i = 0; i < 5; i++) {
                assert(!utxo.exists(txid, i));
            }
        }

        // Test 6: Balance tracking
        {
            auto kp2 = generate_keypair();
            auto pkh2 = compute_pkh(kp2.pubkey);

            auto txid_a = make_txid(200);
            auto txid_b = make_txid(201);

            UTXOEntry entry;
            entry.pubkey_hash = pkh2;
            entry.height = 20;
            entry.is_coinbase = false;

            entry.value = 30 * COIN;
            utxo.add(txid_a, 0, entry);

            entry.value = 20 * COIN;
            utxo.add(txid_b, 0, entry);

            // Balance should be 50 FLC
            Amount balance = utxo.get_balance(pkh2);
            assert(balance == 50 * COIN);

            // Remove one, balance should drop
            utxo.remove(txid_a, 0);
            balance = utxo.get_balance(pkh2);
            assert(balance == 20 * COIN);

            // Remove the other
            utxo.remove(txid_b, 0);
            balance = utxo.get_balance(pkh2);
            assert(balance == 0);
        }

        // Test 7: Rollback preserves original state
        {
            auto txid = make_txid(300);
            UTXOEntry entry;
            entry.value = 100 * COIN;
            entry.pubkey_hash = pkh;
            entry.height = 30;
            entry.is_coinbase = false;

            // Add outside transaction
            utxo.add(txid, 0, entry);
            assert(utxo.exists(txid, 0));

            // Begin, add more, then rollback
            utxo.begin_transaction();
            auto txid2 = make_txid(301);
            utxo.add(txid2, 0, entry);
            utxo.rollback_transaction();

            // The original should still exist
            assert(utxo.exists(txid, 0));
            // The rolled-back one should not
            assert(!utxo.exists(txid2, 0));

            // Cleanup
            utxo.remove(txid, 0);
        }
    }

    // Cleanup
    unlink(db_path.c_str());
    unlink((db_path + "-wal").c_str());
    unlink((db_path + "-shm").c_str());
}
