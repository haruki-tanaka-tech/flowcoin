// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Abstract wallet interface for GUI and external consumers.
// Decouples wallet operations from internal implementation details.
// Supports balance queries, transaction history, sending, UTXO listing,
// encryption, and event notifications.

#ifndef FLOWCOIN_INTERFACES_WALLET_H
#define FLOWCOIN_INTERFACES_WALLET_H

#include "util/types.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace flow {
class Wallet;
class ChainState;
}

namespace flow::interfaces {

// ============================================================================
// WalletInterface
// ============================================================================

class WalletInterface {
public:
    virtual ~WalletInterface() = default;

    // ---- Address management ------------------------------------------------

    /// Generate a new receiving address with an optional label.
    virtual std::string get_new_address(const std::string& label = "") = 0;

    /// Check if an address belongs to this wallet.
    virtual bool is_mine(const std::string& address) = 0;

    /// Get all addresses owned by this wallet.
    virtual std::vector<std::string> get_addresses() = 0;

    /// Get a new address specifically for mining coinbase rewards.
    virtual std::string get_coinbase_address() = 0;

    // ---- Balance -----------------------------------------------------------

    /// Get the confirmed balance (sum of mature, confirmed UTXOs).
    virtual Amount get_balance() = 0;

    /// Get the unconfirmed balance (pending incoming transactions).
    virtual Amount get_unconfirmed_balance() = 0;

    /// Get the immature balance (coinbase outputs not yet mature).
    virtual Amount get_immature_balance() = 0;

    /// Get total balance (confirmed + unconfirmed).
    virtual Amount get_total_balance() = 0;

    // ---- Transaction history -----------------------------------------------

    /// A wallet transaction entry for display.
    struct WalletTx {
        uint256 txid;
        Amount amount = 0;         // net change to wallet balance
        Amount fee = 0;            // fee paid (for sends)
        int confirmations = 0;
        int64_t time = 0;          // timestamp
        std::string address;       // primary address involved
        std::string label;         // user-assigned label
        bool is_send = false;      // true if this wallet sent the tx
        bool is_coinbase = false;  // true if this is a mining reward
    };

    /// Get recent wallet transactions.
    /// @param count  Maximum number of transactions to return.
    /// @param skip   Number of transactions to skip (for pagination).
    virtual std::vector<WalletTx> get_transactions(
        int count = 10, int skip = 0) = 0;

    /// Get details for a specific transaction.
    virtual bool get_transaction(const uint256& txid, WalletTx& wtx) = 0;

    /// Get the total number of wallet transactions.
    virtual size_t get_tx_count() = 0;

    // ---- Sending -----------------------------------------------------------

    /// Result of a send operation.
    struct SendResult {
        bool success = false;
        uint256 txid;
        Amount fee = 0;
        std::string error;
    };

    /// Send coins to an address.
    /// @param address  Destination address (bech32 encoded).
    /// @param amount   Amount to send in atomic units.
    /// @param comment  Optional comment for the transaction.
    virtual SendResult send(const std::string& address, Amount amount,
                            const std::string& comment = "") = 0;

    /// Create a transaction without broadcasting it.
    virtual SendResult create_transaction(const std::string& address,
                                           Amount amount) = 0;

    // ---- UTXOs -------------------------------------------------------------

    /// A single unspent coin.
    struct Coin {
        uint256 txid;
        uint32_t vout = 0;
        Amount value = 0;
        int confirmations = 0;
        bool is_coinbase = false;
        std::string address;
    };

    /// List unspent outputs.
    /// @param min_conf  Minimum confirmations required.
    /// @param max_conf  Maximum confirmations allowed.
    virtual std::vector<Coin> list_unspent(
        int min_conf = 1, int max_conf = 9999999) = 0;

    /// Get the number of unspent outputs.
    virtual size_t utxo_count() = 0;

    // ---- Encryption --------------------------------------------------------

    /// Check if the wallet is encrypted.
    virtual bool is_encrypted() = 0;

    /// Check if the wallet is currently locked.
    virtual bool is_locked() = 0;

    /// Encrypt the wallet with a passphrase.
    virtual bool encrypt(const std::string& passphrase) = 0;

    /// Unlock the wallet for a specified duration.
    /// @param passphrase       The encryption passphrase.
    /// @param timeout_seconds  Duration to remain unlocked (0 = until lock).
    virtual bool unlock(const std::string& passphrase,
                        int timeout_seconds = 0) = 0;

    /// Lock the wallet immediately.
    virtual bool lock() = 0;

    /// Change the wallet passphrase.
    virtual bool change_passphrase(const std::string& old_passphrase,
                                    const std::string& new_passphrase) = 0;

    // ---- Labels ------------------------------------------------------------

    /// Set a label for an address.
    virtual void set_label(const std::string& address,
                            const std::string& label) = 0;

    /// Get the label for an address.
    virtual std::string get_label(const std::string& address) = 0;

    /// Get all addresses with a specific label.
    virtual std::vector<std::string> get_addresses_by_label(
        const std::string& label) = 0;

    // ---- Import / export ---------------------------------------------------

    /// Import a private key (32-byte Ed25519 seed as hex).
    virtual bool import_privkey(const std::string& privkey_hex) = 0;

    /// Backup the wallet to a file.
    virtual bool backup(const std::string& path) = 0;

    // ---- Message signing ---------------------------------------------------

    /// Sign a message with the private key of a wallet address.
    /// Returns the signature as a hex string, or empty on failure.
    virtual std::string sign_message(const std::string& address,
                                      const std::string& message) = 0;

    /// Verify a signed message.
    virtual bool verify_message(const std::string& address,
                                 const std::string& signature,
                                 const std::string& message) = 0;

    // ---- Notifications -----------------------------------------------------

    using TxNotifyCallback = std::function<void(const WalletTx& tx)>;
    using BalanceChangedCallback = std::function<void(Amount balance)>;
    using AddressCallback = std::function<void(const std::string& address)>;

    /// Register callback for incoming/outgoing transactions.
    virtual void register_tx_callback(TxNotifyCallback cb) = 0;

    /// Register callback for balance changes.
    virtual void register_balance_callback(BalanceChangedCallback cb) = 0;

    /// Register callback for new addresses generated.
    virtual void register_address_callback(AddressCallback cb) = 0;

    // ---- Wallet info -------------------------------------------------------

    /// Get the wallet file path.
    virtual std::string get_wallet_path() = 0;

    /// Get the wallet format version.
    virtual int get_wallet_version() = 0;
};

/// Create a WalletInterface wrapping a real Wallet + ChainState.
std::unique_ptr<WalletInterface> make_wallet(Wallet& wallet,
                                              ChainState& chain);

} // namespace flow::interfaces

#endif // FLOWCOIN_INTERFACES_WALLET_H
