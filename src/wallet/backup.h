// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Wallet backup and restore utilities.
// Supports full wallet dump/import, encrypted backup, and key verification.

#pragma once

#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "wallet/encryption.h"

#include <string>
#include <vector>

namespace flow {

namespace backup {

/// Wallet backup metadata header for encrypted backups.
struct BackupHeader {
    uint32_t magic;          // 0x464C4257 ("FLWB")
    uint32_t version;        // Backup format version (1)
    uint32_t key_count;      // Number of keys in backup
    uint32_t addr_count;     // Number of addresses in backup
    int64_t  timestamp;      // Backup creation time
    std::array<uint8_t, 16> salt;  // KDF salt for encryption
    std::array<uint8_t, 32> checksum;  // keccak256 of the plaintext data
};

static constexpr uint32_t BACKUP_MAGIC   = 0x464C4257;
static constexpr uint32_t BACKUP_VERSION = 1;

/// Create an encrypted wallet backup file.
/// The backup contains all keys, addresses, and HD chain state,
/// encrypted with AES-256-CBC using a key derived from the passphrase.
/// @param wallet      The wallet to back up.
/// @param path        Output file path.
/// @param passphrase  Encryption passphrase for the backup.
/// @return            true on success.
bool create_encrypted_backup(const Wallet& wallet, const std::string& path,
                             const std::string& passphrase);

/// Restore a wallet from an encrypted backup file.
/// Decrypts the backup and imports all keys and addresses into the wallet.
/// @param wallet      The wallet to restore into.
/// @param path        Input file path (encrypted backup).
/// @param passphrase  Decryption passphrase.
/// @return            true on success.
bool restore_encrypted_backup(Wallet& wallet, const std::string& path,
                              const std::string& passphrase);

/// Verify the integrity of an encrypted backup without restoring.
/// Checks magic, version, and if the passphrase can decrypt the data.
/// @param path        Backup file path.
/// @param passphrase  Passphrase to verify against.
/// @return            true if the backup is valid and passphrase is correct.
bool verify_backup(const std::string& path, const std::string& passphrase);

/// Count the number of keys in a backup file (without decrypting key data).
/// Returns -1 if the file is not a valid backup.
int count_keys_in_backup(const std::string& path);

/// Export the wallet's master seed as a mnemonic-compatible hex string.
/// The seed is encrypted with the given passphrase before export.
/// @param wallet      The wallet.
/// @param passphrase  Encryption passphrase.
/// @return            Hex-encoded encrypted seed, or empty on error.
std::string export_encrypted_seed(const Wallet& wallet,
                                   const std::string& passphrase);

/// Import a master seed from a mnemonic-compatible hex string.
/// @param wallet      The wallet to import into.
/// @param hex_seed    Hex-encoded encrypted seed.
/// @param passphrase  Decryption passphrase.
/// @return            true on success.
bool import_encrypted_seed(Wallet& wallet, const std::string& hex_seed,
                           const std::string& passphrase);

} // namespace backup
} // namespace flow
