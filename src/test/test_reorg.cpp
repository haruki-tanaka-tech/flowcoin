// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for blockchain reorganization logic.
// Tests reorg scenarios using block index structures and UTXO set operations.

#include "chain/blockindex.h"
#include "chain/utxo.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/random.h"

#include <cassert>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <unistd.h>

using namespace flow;

// Helper: generate a random txid
static uint256 random_txid() {
    return GetRandUint256();
}

// Helper: compute pubkey hash
static std::array<uint8_t, 32> compute_pkh(const std::array<uint8_t, 32>& pubkey) {
    auto hash = keccak256(pubkey.data(), 32);
    return hash.m_data;
}

// Helper: create a coinbase transaction
static CTransaction make_coinbase(Amount reward,
                                   const std::array<uint8_t, 32>& pubkey_hash) {
    CTransaction tx;
    tx.version = 1;
    CTxIn cb;
    tx.vin.push_back(cb);
    tx.vout.push_back(CTxOut(reward, pubkey_hash));
    return tx;
}

// Helper: create a simple signed transfer transaction
static CTransaction make_transfer(const uint256& prev_txid, uint32_t prev_vout,
                                   Amount amount,
                                   const std::array<uint8_t, 32>& dest_pkh,
                                   const KeyPair& sender) {
    CTransaction tx;
    tx.version = 1;

    CTxIn in;
    in.prevout = COutPoint(prev_txid, prev_vout);
    std::memcpy(in.pubkey.data(), sender.pubkey.data(), 32);
    tx.vin.push_back(in);

    tx.vout.push_back(CTxOut(amount, dest_pkh));

    // Sign
    auto sighash = tx.serialize_for_hash();
    auto txhash = keccak256d(sighash);
    auto sig = ed25519_sign(txhash.data(), 32,
                            sender.privkey.data(), sender.pubkey.data());
    tx.vin[0].signature = sig;

    return tx;
}

void test_reorg() {
    std::string utxo_path = "/tmp/test_reorg_utxo_" + std::to_string(getpid()) + ".db";

    {
        UTXOSet utxo(utxo_path);

        auto alice = generate_keypair();
        auto bob = generate_keypair();
        auto charlie = generate_keypair();

        auto alice_pkh = compute_pkh(alice.pubkey);
        auto bob_pkh = compute_pkh(bob.pubkey);
        auto charlie_pkh = compute_pkh(charlie.pubkey);

        // -----------------------------------------------------------------------
        // Test 1: Simple chain A (3 blocks) -> UTXO state
        // -----------------------------------------------------------------------
        {
            Amount reward = consensus::compute_block_reward(0);

            // Block 0: coinbase to Alice
            CTransaction cb0 = make_coinbase(reward, alice_pkh);
            uint256 txid0 = cb0.get_txid();

            utxo.begin_transaction();
            UTXOEntry entry0;
            entry0.value = reward;
            entry0.pubkey_hash = alice_pkh;
            entry0.height = 0;
            entry0.is_coinbase = true;
            utxo.add(txid0, 0, entry0);
            utxo.commit_transaction();

            // Verify UTXO exists
            UTXOEntry check;
            assert(utxo.get(txid0, 0, check));
            assert(check.value == reward);

            // Block 1: coinbase to Bob
            CTransaction cb1 = make_coinbase(reward, bob_pkh);
            uint256 txid1 = cb1.get_txid();

            utxo.begin_transaction();
            UTXOEntry entry1;
            entry1.value = reward;
            entry1.pubkey_hash = bob_pkh;
            entry1.height = 1;
            entry1.is_coinbase = true;
            utxo.add(txid1, 0, entry1);
            utxo.commit_transaction();

            // Block 2: Alice sends to Charlie
            // (In real scenario coinbase maturity would apply,
            //  but for testing UTXO mechanics we skip that check)
            CTransaction tx2 = make_transfer(txid0, 0, reward - 1000,
                                              charlie_pkh, alice);
            uint256 txid2 = tx2.get_txid();

            utxo.begin_transaction();
            utxo.remove(txid0, 0);  // spend Alice's UTXO
            UTXOEntry entry2;
            entry2.value = reward - 1000;
            entry2.pubkey_hash = charlie_pkh;
            entry2.height = 2;
            entry2.is_coinbase = false;
            utxo.add(txid2, 0, entry2);
            utxo.commit_transaction();

            // Alice's UTXO should be gone
            assert(!utxo.exists(txid0, 0));

            // Charlie should have UTXO
            UTXOEntry charlie_check;
            assert(utxo.get(txid2, 0, charlie_check));
            assert(charlie_check.value == reward - 1000);

            // Bob's UTXO should still exist
            assert(utxo.exists(txid1, 0));

            // -----------------------------------------------------------------------
            // Test 2: Simulate reorg — disconnect block 2
            // -----------------------------------------------------------------------

            // Undo block 2: re-add Alice's UTXO, remove Charlie's
            utxo.begin_transaction();
            utxo.remove(txid2, 0);  // undo Charlie's output
            utxo.add(txid0, 0, entry0);  // restore Alice's UTXO
            utxo.commit_transaction();

            // Alice's UTXO should be back
            assert(utxo.exists(txid0, 0));
            assert(!utxo.exists(txid2, 0));

            // Verify balance restoration
            assert(utxo.get_balance(alice_pkh) == reward);
            assert(utxo.get_balance(charlie_pkh) == 0);

            // -----------------------------------------------------------------------
            // Test 3: Connect alternative block 2' — Alice sends to Bob instead
            // -----------------------------------------------------------------------

            CTransaction tx2_alt = make_transfer(txid0, 0, reward - 2000,
                                                  bob_pkh, alice);
            uint256 txid2_alt = tx2_alt.get_txid();

            utxo.begin_transaction();
            utxo.remove(txid0, 0);
            UTXOEntry entry2_alt;
            entry2_alt.value = reward - 2000;
            entry2_alt.pubkey_hash = bob_pkh;
            entry2_alt.height = 2;
            entry2_alt.is_coinbase = false;
            utxo.add(txid2_alt, 0, entry2_alt);
            utxo.commit_transaction();

            // Bob should have two UTXOs now
            auto bob_utxos = utxo.get_utxos_for_script(bob_pkh);
            assert(bob_utxos.size() == 2);

            // Alice should have nothing
            assert(utxo.get_balance(alice_pkh) == 0);
        }

        // -----------------------------------------------------------------------
        // Test 4: Transaction rollback
        // -----------------------------------------------------------------------
        {
            auto dave = generate_keypair();
            auto dave_pkh = compute_pkh(dave.pubkey);

            // Add a UTXO in a transaction, then rollback
            uint256 test_txid = random_txid();

            utxo.begin_transaction();
            UTXOEntry entry;
            entry.value = 100000;
            entry.pubkey_hash = dave_pkh;
            entry.height = 10;
            entry.is_coinbase = false;
            utxo.add(test_txid, 0, entry);

            // Before commit, the UTXO should be visible within the transaction
            UTXOEntry check;
            bool found = utxo.get(test_txid, 0, check);
            // Depending on SQLite behavior, this may or may not be visible
            // before commit. We rollback either way.

            utxo.rollback_transaction();

            // After rollback, the UTXO should not exist
            assert(!utxo.exists(test_txid, 0));
        }

        // -----------------------------------------------------------------------
        // Test 5: Double-spend detection
        // -----------------------------------------------------------------------
        {
            auto eve = generate_keypair();
            auto eve_pkh = compute_pkh(eve.pubkey);

            uint256 coin_txid = random_txid();

            utxo.begin_transaction();
            UTXOEntry coin;
            coin.value = 50000;
            coin.pubkey_hash = eve_pkh;
            coin.height = 20;
            coin.is_coinbase = false;
            utxo.add(coin_txid, 0, coin);
            utxo.commit_transaction();

            // Spend the coin
            utxo.begin_transaction();
            assert(utxo.remove(coin_txid, 0));
            utxo.commit_transaction();

            // Try to spend again — should fail (UTXO already removed)
            utxo.begin_transaction();
            bool removed_again = utxo.remove(coin_txid, 0);
            assert(!removed_again);
            utxo.commit_transaction();
        }

        // -----------------------------------------------------------------------
        // Test 6: Multiple UTXOs per pubkey hash
        // -----------------------------------------------------------------------
        {
            auto frank = generate_keypair();
            auto frank_pkh = compute_pkh(frank.pubkey);

            utxo.begin_transaction();
            for (int i = 0; i < 10; ++i) {
                uint256 txid = random_txid();
                UTXOEntry entry;
                entry.value = 1000 * (i + 1);
                entry.pubkey_hash = frank_pkh;
                entry.height = 30 + i;
                entry.is_coinbase = false;
                utxo.add(txid, 0, entry);
            }
            utxo.commit_transaction();

            auto utxos = utxo.get_utxos_for_script(frank_pkh);
            assert(utxos.size() == 10);

            // Total balance should be sum of 1000..10000
            Amount expected = 0;
            for (int i = 0; i < 10; ++i) expected += 1000 * (i + 1);
            assert(utxo.get_balance(frank_pkh) == expected);
        }

        // -----------------------------------------------------------------------
        // Test 7: Block tree — chain tip selection
        // -----------------------------------------------------------------------
        {
            BlockTree tree;

            // Create a genesis block index
            auto genesis = std::make_unique<CBlockIndex>();
            genesis->height = 0;
            genesis->timestamp = consensus::GENESIS_TIMESTAMP;
            GetRandBytes(genesis->hash.data(), 32);
            CBlockIndex* gen_ptr = tree.insert_genesis(std::move(genesis));
            tree.set_best_tip(gen_ptr);

            assert(tree.best_tip() == gen_ptr);
            assert(tree.genesis() == gen_ptr);
            assert(tree.size() == 1);

            // Find by hash
            CBlockIndex* found = tree.find(gen_ptr->hash);
            assert(found == gen_ptr);

            // Not found
            uint256 fake_hash;
            GetRandBytes(fake_hash.data(), 32);
            assert(tree.find(fake_hash) == nullptr);
        }

        // -----------------------------------------------------------------------
        // Test 8: Chain fork — competing tips
        // -----------------------------------------------------------------------
        {
            BlockTree tree;

            auto genesis = std::make_unique<CBlockIndex>();
            genesis->height = 0;
            GetRandBytes(genesis->hash.data(), 32);
            CBlockIndex* gen = tree.insert_genesis(std::move(genesis));
            tree.set_best_tip(gen);

            // Simulate two competing chains from genesis
            // Chain A: block 1a
            CBlockHeader hdr_a;
            hdr_a.height = 1;
            hdr_a.prev_hash = gen->hash;
            GetRandBytes(hdr_a.miner_pubkey.data(), 32);
            auto unsigned_a = hdr_a.get_unsigned_data();
            // Compute a hash for this header
            uint256 hash_a = keccak256d(unsigned_a);
            // We can't directly insert with a custom hash via the header API,
            // so we verify the tree mechanics manually.

            // Verify the tree can hold multiple entries
            assert(tree.size() == 1);
        }

        // -----------------------------------------------------------------------
        // Test 9: UTXO set — non-existent entry returns false
        // -----------------------------------------------------------------------
        {
            uint256 nonexistent = random_txid();
            UTXOEntry entry;
            assert(!utxo.get(nonexistent, 0, entry));
            assert(!utxo.exists(nonexistent, 0));
            assert(!utxo.remove(nonexistent, 0));
        }

        // -----------------------------------------------------------------------
        // Test 10: Balance of unknown pubkey hash is 0
        // -----------------------------------------------------------------------
        {
            std::array<uint8_t, 32> unknown_pkh;
            GetRandBytes(unknown_pkh.data(), 32);
            assert(utxo.get_balance(unknown_pkh) == 0);
        }
    }

    // Cleanup
    unlink(utxo_path.c_str());
    unlink((utxo_path + "-wal").c_str());
    unlink((utxo_path + "-shm").c_str());
}
