// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for the wallet database layer.

#include "wallet/walletdb.h"
#include "hash/keccak.h"
#include "util/random.h"

#include <cassert>
#include <cstring>
#include <stdexcept>
#include <unistd.h>

using namespace flow;

static std::array<uint8_t, 32> make_random_key() {
    std::array<uint8_t, 32> key;
    GetRandBytes(key.data(), 32);
    return key;
}

void test_chaindb() {
    std::string db_path = "/tmp/test_chaindb_" + std::to_string(getpid()) + ".dat";

    {
        WalletDB db(db_path);

        // -----------------------------------------------------------------------
        // Test 1: Master seed round-trip
        // -----------------------------------------------------------------------
        {
            std::vector<uint8_t> seed(32, 0xAB);
            assert(db.store_master_seed(seed));

            std::vector<uint8_t> loaded;
            assert(db.load_master_seed(loaded));
            assert(loaded.size() == 32);
            assert(std::memcmp(loaded.data(), seed.data(), 32) == 0);
            assert(db.has_master_seed());
        }

        // -----------------------------------------------------------------------
        // Test 2: HD index round-trip
        // -----------------------------------------------------------------------
        {
            assert(db.store_hd_index(42));
            assert(db.load_hd_index() == 42);

            assert(db.store_hd_index(0));
            assert(db.load_hd_index() == 0);

            assert(db.store_hd_index(1000000));
            assert(db.load_hd_index() == 1000000);

            // Max value
            assert(db.store_hd_index(0xFFFFFFFF));
            assert(db.load_hd_index() == 0xFFFFFFFF);
        }

        // -----------------------------------------------------------------------
        // Test 3: Key storage round-trip
        // -----------------------------------------------------------------------
        {
            WalletDB::KeyRecord kr;
            kr.pubkey = make_random_key();
            kr.derivation_path = "m/44'/9555'/0'/0'/0'";
            kr.encrypted_privkey.resize(32, 0x55);

            assert(db.store_key(kr));

            WalletDB::KeyRecord loaded;
            assert(db.load_key(kr.pubkey, loaded));
            assert(loaded.derivation_path == kr.derivation_path);
            assert(loaded.encrypted_privkey.size() == 32);
            assert(loaded.pubkey == kr.pubkey);
        }

        // -----------------------------------------------------------------------
        // Test 4: Load all keys
        // -----------------------------------------------------------------------
        {
            // Store a second key
            WalletDB::KeyRecord kr2;
            kr2.pubkey = make_random_key();
            kr2.derivation_path = "m/44'/9555'/0'/0'/1'";
            kr2.encrypted_privkey.resize(32, 0x66);
            assert(db.store_key(kr2));

            auto all = db.load_all_keys();
            assert(all.size() >= 2);
        }

        // -----------------------------------------------------------------------
        // Test 5: Address storage round-trip
        // -----------------------------------------------------------------------
        {
            WalletDB::AddressRecord ar;
            ar.address = "fl1qtest123";
            ar.pubkey = make_random_key();
            ar.hd_index = 5;
            ar.created_at = 1700000000;

            assert(db.store_address(ar));
            assert(db.has_address("fl1qtest123"));
            assert(!db.has_address("fl1qnonexistent"));

            auto all_addrs = db.load_all_addresses();
            bool found = false;
            for (const auto& a : all_addrs) {
                if (a.address == "fl1qtest123") {
                    found = true;
                    assert(a.hd_index == 5);
                    assert(a.created_at == 1700000000);
                    break;
                }
            }
            assert(found);
        }

        // -----------------------------------------------------------------------
        // Test 6: Transaction storage round-trip
        // -----------------------------------------------------------------------
        {
            WalletDB::WalletTx tx1;
            GetRandBytes(tx1.txid.data(), 32);
            tx1.timestamp = 1700000100;
            tx1.amount = 5000000000LL;
            tx1.block_height = 100;
            tx1.label = "mining reward";

            assert(db.store_tx(tx1));

            WalletDB::WalletTx tx2;
            GetRandBytes(tx2.txid.data(), 32);
            tx2.timestamp = 1700000200;
            tx2.amount = -100000000LL;
            tx2.block_height = 101;
            tx2.label = "payment";

            assert(db.store_tx(tx2));

            auto txs = db.load_transactions(10, 0);
            assert(txs.size() >= 2);

            // Newest first
            assert(txs[0].timestamp >= txs[1].timestamp);

            // Test skip
            auto txs_skip = db.load_transactions(1, 1);
            assert(txs_skip.size() == 1);
        }

        // -----------------------------------------------------------------------
        // Test 7: Transaction update (upsert)
        // -----------------------------------------------------------------------
        {
            WalletDB::WalletTx tx;
            GetRandBytes(tx.txid.data(), 32);
            tx.timestamp = 1700000300;
            tx.amount = 1000;
            tx.block_height = 0;  // unconfirmed
            tx.label = "";

            assert(db.store_tx(tx));

            // Update with confirmation
            tx.block_height = 200;
            tx.label = "confirmed";
            assert(db.store_tx(tx));

            // Load and verify the update
            auto txs = db.load_transactions(100, 0);
            bool found = false;
            for (const auto& t : txs) {
                if (t.txid == tx.txid) {
                    assert(t.block_height == 200);
                    assert(t.label == "confirmed");
                    found = true;
                    break;
                }
            }
            assert(found);
        }

        // -----------------------------------------------------------------------
        // Test 8: Label storage round-trip
        // -----------------------------------------------------------------------
        {
            assert(db.store_label("fl1qabc", "savings"));
            assert(db.load_label("fl1qabc") == "savings");
            assert(db.load_label("fl1qnonexistent") == "");

            assert(db.store_label("fl1qdef", "mining"));

            auto labels = db.load_all_labels();
            assert(labels.size() >= 2);
        }

        // -----------------------------------------------------------------------
        // Test 9: Key not found returns false
        // -----------------------------------------------------------------------
        {
            auto random_pk = make_random_key();
            WalletDB::KeyRecord kr;
            assert(!db.load_key(random_pk, kr));
        }

        // -----------------------------------------------------------------------
        // Test 10: Multiple addresses in order
        // -----------------------------------------------------------------------
        {
            for (uint32_t i = 10; i < 20; ++i) {
                WalletDB::AddressRecord ar;
                ar.address = "fl1qaddr" + std::to_string(i);
                ar.pubkey = make_random_key();
                ar.hd_index = i;
                ar.created_at = 1700000000 + i;
                db.store_address(ar);
            }

            auto addrs = db.load_all_addresses();
            // Verify ordering by hd_index
            for (size_t i = 1; i < addrs.size(); ++i) {
                assert(addrs[i].hd_index >= addrs[i - 1].hd_index);
            }
        }

        // -----------------------------------------------------------------------
        // Test 11: Overwrite master seed
        // -----------------------------------------------------------------------
        {
            std::vector<uint8_t> new_seed(64, 0xCC);  // different size
            assert(db.store_master_seed(new_seed));

            std::vector<uint8_t> loaded;
            assert(db.load_master_seed(loaded));
            assert(loaded.size() == 64);
            assert(loaded[0] == 0xCC);
        }

        // -----------------------------------------------------------------------
        // Test 12: Empty transactions list
        // -----------------------------------------------------------------------
        {
            // With large skip, should return empty
            auto txs = db.load_transactions(10, 100000);
            assert(txs.empty());
        }
    }

    // Cleanup
    unlink(db_path.c_str());
    // Also remove WAL and SHM files
    unlink((db_path + "-wal").c_str());
    unlink((db_path + "-shm").c_str());
}
