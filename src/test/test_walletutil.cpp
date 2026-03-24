// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for wallet utility functions: wallet database operations,
// path handling, and backup functionality.

#include "wallet/walletdb.h"
#include "crypto/keys.h"
#include "hash/keccak.h"
#include "util/types.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

void test_walletutil() {
    using namespace flow;

    std::string wallet_path = "/tmp/flowcoin_test_walletutil.db";
    std::string backup_path = "/tmp/flowcoin_test_walletutil_backup.db";

    // Cleanup from previous runs
    unlink(wallet_path.c_str());
    unlink((wallet_path + "-wal").c_str());
    unlink((wallet_path + "-shm").c_str());
    unlink(backup_path.c_str());
    unlink((backup_path + "-wal").c_str());
    unlink((backup_path + "-shm").c_str());

    // Test 1: WalletDB creates database and tables
    {
        WalletDB db(wallet_path);

        // Should be able to check for master seed (none yet)
        assert(!db.has_master_seed());
    }

    // Test 2: Master seed store and load round-trip
    {
        WalletDB db(wallet_path);

        std::vector<uint8_t> seed = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        };

        assert(db.store_master_seed(seed));
        assert(db.has_master_seed());

        std::vector<uint8_t> loaded;
        assert(db.load_master_seed(loaded));
        assert(loaded.size() == seed.size());
        assert(std::memcmp(loaded.data(), seed.data(), seed.size()) == 0);
    }

    // Test 3: HD index store and load
    {
        WalletDB db(wallet_path);

        assert(db.store_hd_index(0));
        assert(db.load_hd_index() == 0);

        assert(db.store_hd_index(42));
        assert(db.load_hd_index() == 42);

        assert(db.store_hd_index(1000));
        assert(db.load_hd_index() == 1000);
    }

    // Test 4: Key storage round-trip
    {
        WalletDB db(wallet_path);

        auto kp = generate_keypair();

        WalletDB::KeyRecord key;
        key.derivation_path = "m/44'/9555'/0'/0'/0'";
        key.pubkey = kp.pubkey;
        key.encrypted_privkey.assign(kp.privkey.begin(), kp.privkey.end());

        assert(db.store_key(key));

        WalletDB::KeyRecord loaded;
        assert(db.load_key(kp.pubkey, loaded));
        assert(loaded.derivation_path == key.derivation_path);
        assert(loaded.pubkey == key.pubkey);
        assert(loaded.encrypted_privkey.size() == key.encrypted_privkey.size());
        assert(std::memcmp(loaded.encrypted_privkey.data(),
                           key.encrypted_privkey.data(),
                           key.encrypted_privkey.size()) == 0);
    }

    // Test 5: Address storage
    {
        WalletDB db(wallet_path);

        auto kp = generate_keypair();

        WalletDB::AddressRecord addr;
        addr.address = "fl1qtest123456789";
        addr.pubkey = kp.pubkey;
        addr.hd_index = 0;
        addr.created_at = 1742515200;

        assert(db.store_address(addr));
        assert(db.has_address("fl1qtest123456789"));
        assert(!db.has_address("fl1qnonexistent"));

        auto all_addrs = db.load_all_addresses();
        bool found = false;
        for (const auto& a : all_addrs) {
            if (a.address == "fl1qtest123456789") {
                found = true;
                assert(a.pubkey == kp.pubkey);
                assert(a.hd_index == 0);
                break;
            }
        }
        assert(found);
    }

    // Test 6: Transaction history
    {
        WalletDB db(wallet_path);

        WalletDB::WalletTx tx1;
        tx1.txid.set_null();
        tx1.txid[0] = 0x01;
        tx1.timestamp = 1742515200;
        tx1.amount = 50 * COIN;
        tx1.block_height = 1;
        tx1.label = "received";

        WalletDB::WalletTx tx2;
        tx2.txid.set_null();
        tx2.txid[0] = 0x02;
        tx2.timestamp = 1742515800;
        tx2.amount = -10 * COIN;
        tx2.block_height = 2;
        tx2.label = "sent";

        assert(db.store_tx(tx1));
        assert(db.store_tx(tx2));

        auto txs = db.load_transactions(10, 0);
        assert(txs.size() >= 2);
    }

    // Test 7: Backup creates a copy of the database
    {
        // Verify the wallet database file exists
        std::ifstream src_check(wallet_path);
        assert(src_check.good());
        src_check.close();

        // Create a backup by copying the file
        std::ifstream src(wallet_path, std::ios::binary);
        std::ofstream dst(backup_path, std::ios::binary);
        assert(src.good());
        assert(dst.good());
        dst << src.rdbuf();
        src.close();
        dst.close();

        // Verify backup exists and is readable
        std::ifstream backup_check(backup_path);
        assert(backup_check.good());
        backup_check.close();

        // Open the backup and verify it has the same data
        WalletDB backup_db(backup_path);
        assert(backup_db.has_master_seed());

        std::vector<uint8_t> seed;
        assert(backup_db.load_master_seed(seed));
        assert(seed.size() == 32);
    }

    // Test 8: Load all keys
    {
        WalletDB db(wallet_path);
        auto all_keys = db.load_all_keys();
        assert(!all_keys.empty());

        // Verify each key has required fields
        for (const auto& key : all_keys) {
            assert(!key.derivation_path.empty());
            bool pubkey_nonzero = false;
            for (auto b : key.pubkey) {
                if (b != 0) { pubkey_nonzero = true; break; }
            }
            assert(pubkey_nonzero);
            assert(!key.encrypted_privkey.empty());
        }
    }

    // Cleanup
    unlink(wallet_path.c_str());
    unlink((wallet_path + "-wal").c_str());
    unlink((wallet_path + "-shm").c_str());
    unlink(backup_path.c_str());
    unlink((backup_path + "-wal").c_str());
    unlink((backup_path + "-shm").c_str());
}
