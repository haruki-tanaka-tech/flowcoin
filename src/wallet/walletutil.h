// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Wallet utility functions: file management, backup, dump, and import.

#pragma once

#include <string>

namespace flow {

class Wallet;

namespace walletutil {

/// Return the default wallet database path for a given data directory.
/// The returned path is datadir + "/wallet.dat" (flat, Bitcoin-legacy layout).
std::string get_wallet_path(const std::string& datadir);

/// Check whether a wallet file exists at the given path.
bool wallet_exists(const std::string& path);

/// Copy the wallet file to a backup location.
/// The wallet should not be actively written during this call; callers
/// should coordinate with the wallet lock.
/// @param wallet_path  Path to the wallet.dat file.
/// @param backup_path  Destination path for the backup copy.
/// @return             true on success.
bool backup_wallet(const std::string& wallet_path, const std::string& backup_path);

/// Dump all wallet keys and addresses to a human-readable text file.
/// Each line is one of:
///   KEY <hex_privkey> <hex_pubkey> <address> <derivation_path> <created_at>
///   HDI <next_hd_index>
///   # comment/metadata lines
///
/// @param wallet  The wallet to dump.
/// @param path    Output file path.
/// @return        true on success.
bool dump_wallet(const Wallet& wallet, const std::string& path);

/// Import keys from a previously dumped wallet file.
/// Reads lines in the dump format and calls wallet.import_privkey() for
/// each KEY entry found. Skips lines that are comments or unrecognized.
/// @param wallet  The wallet to import into.
/// @param path    Input file path (dump format).
/// @return        true if at least one key was imported.
bool import_wallet(Wallet& wallet, const std::string& path);

/// Return a human-readable size string for the wallet file (e.g., "1.2 MB").
std::string wallet_file_size(const std::string& path);

} // namespace walletutil
} // namespace flow
