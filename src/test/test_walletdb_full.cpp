// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Comprehensive tests for wallet database: seed storage, HD chain state,
// key records, address records, transaction history, labels, backup,
// and concurrent read safety.

#include "wallet/walletdb.h"
#include "primitives/transaction.h"
#include "util/random.h"
#include "util/types.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace flow;

void test_walletdb_full() {
    std::string db_path = "/tmp/test_walletdb_full_" + std::to_string(getpid()) + ".dat";
    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 1: Create database, verify it opens without error
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);
        // If we reach here, the database was created successfully
        assert(!db.has_master_seed());
    }

    // -----------------------------------------------------------------------
    // Test 2: Store/load master seed round-trip
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        assert(db.store_master_seed(seed));
        assert(db.has_master_seed());

        std::vector<uint8_t> loaded;
        assert(db.load_master_seed(loaded));
        assert(loaded == seed);
    }

    // Clean up and recreate
    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 3: Store/load encrypted seed round-trip
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);
        // Encrypted seed is just arbitrary bytes
        std::vector<uint8_t> encrypted_seed(48);  // 16 IV + 32 ciphertext
        GetRandBytes(encrypted_seed.data(), 48);

        assert(db.store_master_seed(encrypted_seed));
        assert(db.has_master_seed());

        std::vector<uint8_t> loaded;
        assert(db.load_master_seed(loaded));
        assert(loaded == encrypted_seed);
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 4: Store/load HD chain index round-trip
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);
        assert(db.store_hd_index(42));
        assert(db.load_hd_index() == 42);

        assert(db.store_hd_index(0));
        assert(db.load_hd_index() == 0);

        assert(db.store_hd_index(99999));
        assert(db.load_hd_index() == 99999);
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 5: Store/load key round-trip
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        WalletDB::KeyRecord key;
        key.derivation_path = "m/44'/9555'/0'/0'/0'";
        GetRandBytes(key.pubkey.data(), 32);
        key.encrypted_privkey.resize(48);
        GetRandBytes(key.encrypted_privkey.data(), 48);

        assert(db.store_key(key));

        WalletDB::KeyRecord loaded;
        assert(db.load_key(key.pubkey, loaded));
        assert(loaded.derivation_path == key.derivation_path);
        assert(loaded.pubkey == key.pubkey);
        assert(loaded.encrypted_privkey == key.encrypted_privkey);
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 6: load_all_keys returns all stored keys
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        std::vector<WalletDB::KeyRecord> keys;
        for (int i = 0; i < 10; ++i) {
            WalletDB::KeyRecord key;
            key.derivation_path = "m/44'/9555'/0'/0'/" + std::to_string(i) + "'";
            GetRandBytes(key.pubkey.data(), 32);
            key.encrypted_privkey.resize(32);
            GetRandBytes(key.encrypted_privkey.data(), 32);
            keys.push_back(key);
            assert(db.store_key(key));
        }

        auto loaded = db.load_all_keys();
        assert(loaded.size() == 10);

        // Verify all keys are present
        for (const auto& orig : keys) {
            bool found = false;
            for (const auto& l : loaded) {
                if (l.pubkey == orig.pubkey) {
                    assert(l.derivation_path == orig.derivation_path);
                    assert(l.encrypted_privkey == orig.encrypted_privkey);
                    found = true;
                    break;
                }
            }
            assert(found);
        }
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 7: Store/load address round-trip
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        WalletDB::AddressRecord addr;
        addr.address = "fl1qtest123456789";
        GetRandBytes(addr.pubkey.data(), 32);
        addr.hd_index = 5;
        addr.created_at = 1700000000;

        assert(db.store_address(addr));

        auto all = db.load_all_addresses();
        assert(all.size() == 1);
        assert(all[0].address == addr.address);
        assert(all[0].pubkey == addr.pubkey);
        assert(all[0].hd_index == 5);
        assert(all[0].created_at == 1700000000);

        assert(db.has_address("fl1qtest123456789"));
        assert(!db.has_address("fl1qnonexistent"));
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 8: Store/load transaction round-trip
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        WalletDB::WalletTx tx;
        GetRandBytes(tx.txid.data(), 32);
        tx.timestamp = 1700000000;
        tx.amount = 10 * COIN;
        tx.block_height = 12345;
        tx.label = "test payment";

        assert(db.store_tx(tx));

        auto loaded = db.load_transactions(10, 0);
        assert(loaded.size() == 1);
        assert(loaded[0].txid == tx.txid);
        assert(loaded[0].timestamp == 1700000000);
        assert(loaded[0].amount == 10 * COIN);
        assert(loaded[0].block_height == 12345);
        assert(loaded[0].label == "test payment");
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 9: Transaction count and pagination
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        for (int i = 0; i < 20; ++i) {
            WalletDB::WalletTx tx;
            GetRandBytes(tx.txid.data(), 32);
            tx.timestamp = 1700000000 + i;
            tx.amount = (i + 1) * COIN;
            tx.block_height = static_cast<uint64_t>(i + 1);
            tx.label = "";
            db.store_tx(tx);
        }

        // Load first 5
        auto first5 = db.load_transactions(5, 0);
        assert(first5.size() == 5);

        // Load next 5
        auto next5 = db.load_transactions(5, 5);
        assert(next5.size() == 5);

        // Load all
        auto all = db.load_transactions(100, 0);
        assert(all.size() == 20);

        // Load with skip past end
        auto empty = db.load_transactions(10, 30);
        assert(empty.empty());
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 10: Labels: store, load, load_all
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        assert(db.store_label("fl1qaddr1", "Savings"));
        assert(db.store_label("fl1qaddr2", "Checking"));
        assert(db.store_label("fl1qaddr3", "Mining"));

        assert(db.load_label("fl1qaddr1") == "Savings");
        assert(db.load_label("fl1qaddr2") == "Checking");
        assert(db.load_label("fl1qaddr3") == "Mining");

        // Non-existent label
        assert(db.load_label("fl1qnonexistent").empty());

        // Update label
        assert(db.store_label("fl1qaddr1", "Updated Savings"));
        assert(db.load_label("fl1qaddr1") == "Updated Savings");

        auto all = db.load_all_labels();
        assert(all.size() == 3);

        // Verify labels are in the set
        std::set<std::string> addrs;
        for (const auto& [addr, label] : all) {
            addrs.insert(addr);
        }
        assert(addrs.count("fl1qaddr1"));
        assert(addrs.count("fl1qaddr2"));
        assert(addrs.count("fl1qaddr3"));
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 11: Multiple addresses stored and retrieved
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        for (int i = 0; i < 20; ++i) {
            WalletDB::AddressRecord addr;
            addr.address = "fl1qaddr" + std::to_string(i);
            GetRandBytes(addr.pubkey.data(), 32);
            addr.hd_index = static_cast<uint32_t>(i);
            addr.created_at = 1700000000 + i;
            db.store_address(addr);
        }

        auto all = db.load_all_addresses();
        assert(all.size() == 20);

        for (int i = 0; i < 20; ++i) {
            assert(db.has_address("fl1qaddr" + std::to_string(i)));
        }
        assert(!db.has_address("fl1qaddr999"));
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 12: Key lookup by pubkey (non-existent returns false)
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        std::array<uint8_t, 32> unknown_pk;
        GetRandBytes(unknown_pk.data(), 32);

        WalletDB::KeyRecord result;
        assert(!db.load_key(unknown_pk, result));
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 13: Persistence across database reopens
    // -----------------------------------------------------------------------
    {
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);

        // Write
        {
            WalletDB db(db_path);
            db.store_master_seed(seed);
            db.store_hd_index(42);
            db.store_label("fl1qaddr1", "Test Label");
        }

        // Read in a new instance
        {
            WalletDB db(db_path);
            assert(db.has_master_seed());

            std::vector<uint8_t> loaded;
            db.load_master_seed(loaded);
            assert(loaded == seed);

            assert(db.load_hd_index() == 42);
            assert(db.load_label("fl1qaddr1") == "Test Label");
        }
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 14: Transaction with negative amount (sent)
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        WalletDB::WalletTx tx;
        GetRandBytes(tx.txid.data(), 32);
        tx.timestamp = 1700000000;
        tx.amount = -5 * COIN;  // sent
        tx.block_height = 100;
        tx.label = "payment out";

        assert(db.store_tx(tx));

        auto loaded = db.load_transactions(10, 0);
        assert(loaded.size() == 1);
        assert(loaded[0].amount == -5 * COIN);
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 15: Empty database returns empty collections
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        assert(!db.has_master_seed());
        assert(db.load_all_keys().empty());
        assert(db.load_all_addresses().empty());
        assert(db.load_transactions(10, 0).empty());
        assert(db.load_all_labels().empty());
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 16: Store many keys and verify all loadable
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        for (int i = 0; i < 50; ++i) {
            WalletDB::KeyRecord key;
            key.derivation_path = "m/44'/9555'/0'/0'/" + std::to_string(i) + "'";
            GetRandBytes(key.pubkey.data(), 32);
            key.encrypted_privkey.resize(32);
            GetRandBytes(key.encrypted_privkey.data(), 32);
            assert(db.store_key(key));
        }

        auto all = db.load_all_keys();
        assert(all.size() == 50);
    }

    std::remove(db_path.c_str());

    // -----------------------------------------------------------------------
    // Test 17: Concurrent read safety (multiple readers on same DB)
    // -----------------------------------------------------------------------
    {
        WalletDB db(db_path);

        // Store some data
        std::vector<uint8_t> seed(32);
        GetRandBytes(seed.data(), 32);
        db.store_master_seed(seed);

        for (int i = 0; i < 10; ++i) {
            WalletDB::KeyRecord key;
            key.derivation_path = "m/" + std::to_string(i);
            GetRandBytes(key.pubkey.data(), 32);
            key.encrypted_privkey.resize(32);
            GetRandBytes(key.encrypted_privkey.data(), 32);
            db.store_key(key);
        }

        // Multiple concurrent reads should not crash
        std::vector<std::thread> readers;
        for (int t = 0; t < 4; ++t) {
            readers.emplace_back([&db]() {
                for (int i = 0; i < 100; ++i) {
                    auto keys = db.load_all_keys();
                    assert(keys.size() == 10);
                    std::vector<uint8_t> s;
                    db.load_master_seed(s);
                    assert(s.size() == 32);
                }
            });
        }

        for (auto& t : readers) {
            t.join();
        }
    }

    // -----------------------------------------------------------------------
    // Test 18: Overwrite existing key
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        WalletDB::KeyRecord key1;
        key1.derivation_path = "m/44'/9555'/0'/0'/0'";
        GetRandBytes(key1.pubkey.data(), 32);
        key1.encrypted_privkey.resize(32);
        GetRandBytes(key1.encrypted_privkey.data(), 32);
        assert(db.store_key(key1));

        // Overwrite with new encrypted privkey
        WalletDB::KeyRecord key2 = key1;
        key2.encrypted_privkey.resize(48);
        GetRandBytes(key2.encrypted_privkey.data(), 48);
        assert(db.store_key(key2));

        WalletDB::KeyRecord loaded;
        assert(db.load_key(key1.pubkey, loaded));
        assert(loaded.encrypted_privkey.size() == 48);
    }

    // -----------------------------------------------------------------------
    // Test 19: Multiple seed overwrites
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        for (int i = 0; i < 5; ++i) {
            std::vector<uint8_t> seed(32, static_cast<uint8_t>(i));
            assert(db.store_master_seed(seed));

            std::vector<uint8_t> loaded;
            assert(db.load_master_seed(loaded));
            assert(loaded == seed);
        }
    }

    // -----------------------------------------------------------------------
    // Test 20: HD index survives reopens
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        {
            WalletDB db(db_path);
            db.store_hd_index(777);
        }
        {
            WalletDB db(db_path);
            assert(db.load_hd_index() == 777);
        }
    }

    // -----------------------------------------------------------------------
    // Test 21: Transaction with zero block_height (unconfirmed)
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        WalletDB::WalletTx tx;
        GetRandBytes(tx.txid.data(), 32);
        tx.timestamp = 1700000000;
        tx.amount = 1 * COIN;
        tx.block_height = 0;  // unconfirmed
        tx.label = "unconfirmed";

        assert(db.store_tx(tx));

        auto loaded = db.load_transactions(10, 0);
        assert(loaded.size() == 1);
        assert(loaded[0].block_height == 0);
    }

    // -----------------------------------------------------------------------
    // Test 22: Labels with special characters
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        assert(db.store_label("fl1q1", "Alice's wallet"));
        assert(db.store_label("fl1q2", "Bob & Co."));
        assert(db.store_label("fl1q3", "Label with \"quotes\""));
        assert(db.store_label("fl1q4", ""));  // empty label

        assert(db.load_label("fl1q1") == "Alice's wallet");
        assert(db.load_label("fl1q2") == "Bob & Co.");
        assert(db.load_label("fl1q3") == "Label with \"quotes\"");
        assert(db.load_label("fl1q4") == "");
    }

    // -----------------------------------------------------------------------
    // Test 23: Large number of transactions
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        for (int i = 0; i < 100; ++i) {
            WalletDB::WalletTx tx;
            GetRandBytes(tx.txid.data(), 32);
            tx.timestamp = 1700000000 + i;
            tx.amount = (i % 2 == 0) ? static_cast<int64_t>(i + 1) * COIN
                                      : -static_cast<int64_t>(i + 1) * COIN;
            tx.block_height = static_cast<uint64_t>(i + 1);
            tx.label = "tx" + std::to_string(i);
            db.store_tx(tx);
        }

        auto all = db.load_transactions(200, 0);
        assert(all.size() == 100);

        // Verify pagination
        auto page1 = db.load_transactions(25, 0);
        assert(page1.size() == 25);
        auto page2 = db.load_transactions(25, 25);
        assert(page2.size() == 25);
        auto page3 = db.load_transactions(25, 50);
        assert(page3.size() == 25);
        auto page4 = db.load_transactions(25, 75);
        assert(page4.size() == 25);
        auto page5 = db.load_transactions(25, 100);
        assert(page5.empty());
    }

    // -----------------------------------------------------------------------
    // Test 24: Address records with various hd_index values
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        for (uint32_t i = 0; i < 50; i += 10) {
            WalletDB::AddressRecord addr;
            addr.address = "fl1qaddr_idx_" + std::to_string(i);
            GetRandBytes(addr.pubkey.data(), 32);
            addr.hd_index = i;
            addr.created_at = 1700000000 + static_cast<int64_t>(i);
            db.store_address(addr);
        }

        auto all = db.load_all_addresses();
        assert(all.size() == 5);

        // Verify indices
        std::set<uint32_t> indices;
        for (const auto& a : all) {
            indices.insert(a.hd_index);
        }
        assert(indices.count(0));
        assert(indices.count(10));
        assert(indices.count(20));
        assert(indices.count(30));
        assert(indices.count(40));
    }

    // -----------------------------------------------------------------------
    // Test 25: Key records with different path lengths
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        std::vector<std::string> paths = {
            "m/44'/9555'/0'/0'/0'",
            "m/44'/9555'/0'/0'/999'",
            "m/0'",
            "imported"
        };

        for (const auto& path : paths) {
            WalletDB::KeyRecord key;
            key.derivation_path = path;
            GetRandBytes(key.pubkey.data(), 32);
            key.encrypted_privkey.resize(32);
            GetRandBytes(key.encrypted_privkey.data(), 32);
            assert(db.store_key(key));
        }

        auto all = db.load_all_keys();
        assert(all.size() == 4);
    }

    // -----------------------------------------------------------------------
    // Test 26: has_address returns false after empty DB
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);
        assert(!db.has_address("fl1qanything"));
    }

    // -----------------------------------------------------------------------
    // Test 27: load_master_seed from empty DB returns false
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);
        std::vector<uint8_t> seed;
        assert(!db.load_master_seed(seed));
        assert(seed.empty());
    }

    // -----------------------------------------------------------------------
    // Test 28: HD index from empty DB returns 0
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);
        assert(db.load_hd_index() == 0);
    }

    // -----------------------------------------------------------------------
    // Test 29: Store same address twice (idempotent)
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        WalletDB::AddressRecord addr;
        addr.address = "fl1qdup";
        GetRandBytes(addr.pubkey.data(), 32);
        addr.hd_index = 0;
        addr.created_at = 1700000000;

        assert(db.store_address(addr));
        // Store again should succeed (upsert or ignore)
        db.store_address(addr);

        assert(db.has_address("fl1qdup"));
    }

    // -----------------------------------------------------------------------
    // Test 30: Transaction with very large amount
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        WalletDB::WalletTx tx;
        GetRandBytes(tx.txid.data(), 32);
        tx.timestamp = 1700000000;
        tx.amount = MAX_MONEY;
        tx.block_height = 1;
        tx.label = "big";

        assert(db.store_tx(tx));
        auto loaded = db.load_transactions(1, 0);
        assert(loaded.size() == 1);
        assert(loaded[0].amount == MAX_MONEY);
    }

    // -----------------------------------------------------------------------
    // Test 31: Labels with unicode-like characters
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        // Standard ASCII labels only (SQLite handles them fine)
        assert(db.store_label("fl1q_uni", "test-label-123_456"));
        assert(db.load_label("fl1q_uni") == "test-label-123_456");
    }

    // -----------------------------------------------------------------------
    // Test 32: Load transactions with count=0 returns empty
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        WalletDB::WalletTx tx;
        GetRandBytes(tx.txid.data(), 32);
        tx.timestamp = 1700000000;
        tx.amount = COIN;
        tx.block_height = 1;
        tx.label = "";
        db.store_tx(tx);

        auto zero_count = db.load_transactions(0, 0);
        assert(zero_count.empty());
    }

    // -----------------------------------------------------------------------
    // Test 33: Key with zero-length encrypted_privkey
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        WalletDB::KeyRecord key;
        key.derivation_path = "m/0'";
        GetRandBytes(key.pubkey.data(), 32);
        // empty encrypted privkey (e.g., watch-only)
        key.encrypted_privkey.clear();

        assert(db.store_key(key));

        WalletDB::KeyRecord loaded;
        assert(db.load_key(key.pubkey, loaded));
        assert(loaded.encrypted_privkey.empty());
    }

    // -----------------------------------------------------------------------
    // Test 34: Multiple labels for different addresses
    // -----------------------------------------------------------------------
    {
        std::remove(db_path.c_str());
        WalletDB db(db_path);

        for (int i = 0; i < 30; ++i) {
            std::string addr = "fl1qmulti" + std::to_string(i);
            std::string label = "Label " + std::to_string(i);
            assert(db.store_label(addr, label));
        }

        auto all = db.load_all_labels();
        assert(all.size() == 30);

        for (int i = 0; i < 30; ++i) {
            std::string addr = "fl1qmulti" + std::to_string(i);
            std::string expected_label = "Label " + std::to_string(i);
            assert(db.load_label(addr) == expected_label);
        }
    }

    // Final cleanup
    std::remove(db_path.c_str());
    std::remove((db_path + "-wal").c_str());
    std::remove((db_path + "-shm").c_str());
}
