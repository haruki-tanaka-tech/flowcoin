// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for wallet backup and restore functionality.

#include "wallet/backup.h"
#include "wallet/encryption.h"
#include "wallet/walletdb.h"
#include "hash/keccak.h"
#include "util/random.h"
#include "util/strencodings.h"

#include <cassert>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <unistd.h>

using namespace flow;

void test_backup() {
    std::string base = "/tmp/test_backup_" + std::to_string(getpid());

    // -----------------------------------------------------------------------
    // Test 1: backup::verify_backup fails on non-existent file
    // -----------------------------------------------------------------------
    {
        bool ok = backup::verify_backup(base + "_nonexistent.bak", "pass");
        assert(!ok);
    }

    // -----------------------------------------------------------------------
    // Test 2: backup::count_keys_in_backup fails on non-existent file
    // -----------------------------------------------------------------------
    {
        int count = backup::count_keys_in_backup(base + "_nonexistent.bak");
        assert(count == -1);
    }

    // -----------------------------------------------------------------------
    // Test 3: backup::verify_backup fails on random data
    // -----------------------------------------------------------------------
    {
        std::string garbage_path = base + "_garbage.bak";
        {
            std::ofstream out(garbage_path, std::ios::binary);
            uint8_t garbage[256];
            GetRandBytes(garbage, 256);
            out.write(reinterpret_cast<const char*>(garbage), 256);
        }

        bool ok = backup::verify_backup(garbage_path, "pass");
        assert(!ok);

        int count = backup::count_keys_in_backup(garbage_path);
        assert(count == -1);

        unlink(garbage_path.c_str());
    }

    // -----------------------------------------------------------------------
    // Test 4: Encrypted seed export/import round-trip concept
    // -----------------------------------------------------------------------
    {
        // Test the encryption layer that would be used for seed export
        std::array<uint8_t, 32> seed;
        GetRandBytes(seed.data(), 32);

        std::array<uint8_t, 16> salt;
        std::memset(salt.data(), 0x42, 16);

        auto aes_key = WalletEncryption::derive_key("test_passphrase", salt);
        auto encrypted = WalletEncryption::encrypt(seed.data(), 32, aes_key);
        auto decrypted = WalletEncryption::decrypt(
            encrypted.data(), encrypted.size(), aes_key);

        assert(decrypted.size() == 32);
        assert(std::memcmp(decrypted.data(), seed.data(), 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 5: Authenticated encryption protects against tampering
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[] = "Important wallet backup data";
        size_t len = sizeof(data) - 1;

        auto encrypted = WalletEncryption::encrypt_authenticated(data, len, key);
        assert(!encrypted.empty());
        // Format: [ciphertext (IV + padded)][32 MAC]
        assert(encrypted.size() >= 64);

        // Valid decryption
        auto decrypted = WalletEncryption::decrypt_authenticated(
            encrypted.data(), encrypted.size(), key);
        assert(decrypted.size() == len);
        assert(std::memcmp(decrypted.data(), data, len) == 0);

        // Tamper with the ciphertext
        std::vector<uint8_t> tampered = encrypted;
        tampered[20] ^= 0xFF;
        auto bad = WalletEncryption::decrypt_authenticated(
            tampered.data(), tampered.size(), key);
        assert(bad.empty());  // MAC check should fail

        // Tamper with the MAC
        std::vector<uint8_t> tampered_mac = encrypted;
        tampered_mac[tampered_mac.size() - 1] ^= 0xFF;
        auto bad2 = WalletEncryption::decrypt_authenticated(
            tampered_mac.data(), tampered_mac.size(), key);
        assert(bad2.empty());

        // Wrong key
        std::array<uint8_t, 32> wrong_key;
        GetRandBytes(wrong_key.data(), 32);
        auto bad3 = WalletEncryption::decrypt_authenticated(
            encrypted.data(), encrypted.size(), wrong_key);
        assert(bad3.empty());
    }

    // -----------------------------------------------------------------------
    // Test 6: Secure wipe zeroes memory
    // -----------------------------------------------------------------------
    {
        uint8_t buffer[64];
        std::memset(buffer, 0xFF, 64);

        WalletEncryption::secure_wipe(buffer, 64);

        for (int i = 0; i < 64; ++i) {
            assert(buffer[i] == 0);
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: Constant-time equal
    // -----------------------------------------------------------------------
    {
        uint8_t a[32], b[32], c[32];
        GetRandBytes(a, 32);
        std::memcpy(b, a, 32);
        GetRandBytes(c, 32);

        assert(WalletEncryption::constant_time_equal(a, b, 32));
        // c is random, extremely unlikely to equal a
        if (std::memcmp(a, c, 32) != 0) {
            assert(!WalletEncryption::constant_time_equal(a, c, 32));
        }

        // Empty comparison
        assert(WalletEncryption::constant_time_equal(a, b, 0));
    }

    // -----------------------------------------------------------------------
    // Test 8: encrypt_privkey / decrypt_privkey round-trip
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> privkey;
        GetRandBytes(privkey.data(), 32);

        std::array<uint8_t, 32> aes_key;
        GetRandBytes(aes_key.data(), 32);

        auto encrypted = WalletEncryption::encrypt_privkey(privkey, aes_key);
        assert(!encrypted.empty());

        auto decrypted = WalletEncryption::decrypt_privkey(encrypted, aes_key);
        assert(decrypted == privkey);
    }

    // -----------------------------------------------------------------------
    // Test 9: encrypt_privkey with wrong key returns garbage
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> privkey;
        GetRandBytes(privkey.data(), 32);

        std::array<uint8_t, 32> key1, key2;
        GetRandBytes(key1.data(), 32);
        GetRandBytes(key2.data(), 32);

        auto encrypted = WalletEncryption::encrypt_privkey(privkey, key1);
        auto decrypted = WalletEncryption::decrypt_privkey(encrypted, key2);
        // With wrong key, either returns all zeros or garbage
        // (since the CBC padding may or may not pass)
        if (decrypted != std::array<uint8_t, 32>{}) {
            assert(decrypted != privkey);
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: Authenticated encryption with empty data
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        auto encrypted = WalletEncryption::encrypt_authenticated(nullptr, 0, key);
        assert(!encrypted.empty());

        auto decrypted = WalletEncryption::decrypt_authenticated(
            encrypted.data(), encrypted.size(), key);
        assert(decrypted.empty());  // 0-length plaintext
    }

    // -----------------------------------------------------------------------
    // Test 11: Authenticated encryption with large data
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        std::vector<uint8_t> large_data(4096);
        GetRandBytes(large_data.data(), large_data.size());

        auto encrypted = WalletEncryption::encrypt_authenticated(
            large_data.data(), large_data.size(), key);

        auto decrypted = WalletEncryption::decrypt_authenticated(
            encrypted.data(), encrypted.size(), key);

        assert(decrypted.size() == 4096);
        assert(decrypted == large_data);
    }

    // -----------------------------------------------------------------------
    // Test 12: Truncated authenticated data fails
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 32> key;
        GetRandBytes(key.data(), 32);

        uint8_t data[] = "test data";
        auto encrypted = WalletEncryption::encrypt_authenticated(data, 9, key);

        // Too short
        auto bad = WalletEncryption::decrypt_authenticated(encrypted.data(), 32, key);
        assert(bad.empty());

        auto bad2 = WalletEncryption::decrypt_authenticated(encrypted.data(), 63, key);
        assert(bad2.empty());
    }

    // -----------------------------------------------------------------------
    // Test 13: WalletDB label operations
    // -----------------------------------------------------------------------
    {
        std::string db_path = base + "_labels.dat";
        {
            WalletDB db(db_path);

            // Store labels
            assert(db.store_label("fl1qaddr1", "personal"));
            assert(db.store_label("fl1qaddr2", "business"));
            assert(db.store_label("fl1qaddr3", "personal"));

            // Load individual
            assert(db.load_label("fl1qaddr1") == "personal");
            assert(db.load_label("fl1qaddr2") == "business");
            assert(db.load_label("fl1qaddr3") == "personal");
            assert(db.load_label("fl1qaddr_none") == "");

            // Load all
            auto all = db.load_all_labels();
            assert(all.size() == 3);

            // Update label
            assert(db.store_label("fl1qaddr1", "updated"));
            assert(db.load_label("fl1qaddr1") == "updated");

            // Clear label
            assert(db.store_label("fl1qaddr2", ""));
            assert(db.load_label("fl1qaddr2") == "");
        }

        unlink(db_path.c_str());
        unlink((db_path + "-wal").c_str());
        unlink((db_path + "-shm").c_str());
    }

    // -----------------------------------------------------------------------
    // Test 14: Key derivation consistency across calls
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 16> salt;
        GetRandBytes(salt.data(), 16);

        // Same passphrase and salt always produces the same key
        auto k1 = WalletEncryption::derive_key("consistent", salt);
        auto k2 = WalletEncryption::derive_key("consistent", salt);
        auto k3 = WalletEncryption::derive_key("consistent", salt);

        assert(k1 == k2);
        assert(k2 == k3);
    }

    // -----------------------------------------------------------------------
    // Test 15: Empty passphrase produces a key (not recommended but valid)
    // -----------------------------------------------------------------------
    {
        std::array<uint8_t, 16> salt;
        GetRandBytes(salt.data(), 16);

        auto key = WalletEncryption::derive_key("", salt);
        // Should be non-zero
        bool all_zero = true;
        for (auto b : key) {
            if (b != 0) { all_zero = false; break; }
        }
        assert(!all_zero);
    }
}
