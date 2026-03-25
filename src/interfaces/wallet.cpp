// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "interfaces/wallet.h"
#include "chain/chainstate.h"
#include "crypto/bech32.h"
#include "hash/keccak.h"
#include "util/strencodings.h"
#include "wallet/wallet.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace flow::interfaces {

// ============================================================================
// WalletImpl: concrete implementation wrapping flow::Wallet
// ============================================================================

class WalletImpl : public WalletInterface {
public:
    WalletImpl(Wallet& wallet, ChainState& chain)
        : wallet_(wallet), chain_(chain) {}

    ~WalletImpl() override = default;

    // ---- Address management ------------------------------------------------

    std::string get_new_address(const std::string& label) override {
        std::string addr = wallet_.get_new_address();
        if (!label.empty() && !addr.empty()) {
            wallet_.set_label(addr, label);
        }
        return addr;
    }

    bool is_mine(const std::string& address) override {
        return wallet_.is_mine(address);
    }

    std::vector<std::string> get_addresses() override {
        return wallet_.get_addresses();
    }

    std::string get_coinbase_address() override {
        return wallet_.get_coinbase_address();
    }

    // ---- Balance -----------------------------------------------------------

    Amount get_balance() override {
        return wallet_.get_balance();
    }

    Amount get_unconfirmed_balance() override {
        // Not directly supported -- return 0
        return 0;
    }

    Amount get_immature_balance() override {
        // Scan for immature coinbase outputs
        Amount immature = 0;
        auto unspent = wallet_.list_unspent();
        uint64_t chain_height = chain_.height();

        for (const auto& coin : unspent) {
            if (coin.is_coinbase) {
                int conf = static_cast<int>(chain_height - coin.height);
                if (conf < 100) {  // COINBASE_MATURITY
                    immature += coin.value;
                }
            }
        }
        return immature;
    }

    Amount get_total_balance() override {
        return get_balance() + get_unconfirmed_balance();
    }

    // ---- Transaction history -----------------------------------------------

    std::vector<WalletTx> get_transactions(int count, int skip) override {
        auto db_txs = wallet_.get_transactions(count, skip);
        std::vector<WalletTx> result;
        result.reserve(db_txs.size());

        for (const auto& dtx : db_txs) {
            WalletTx wtx;
            wtx.txid = dtx.txid;
            wtx.amount = dtx.amount;
            wtx.fee = dtx.fee;
            wtx.confirmations = dtx.confirmations;
            wtx.time = dtx.timestamp;
            wtx.address = dtx.address;
            wtx.label = dtx.label;
            wtx.is_send = dtx.is_send;
            wtx.is_coinbase = dtx.is_coinbase;
            result.push_back(std::move(wtx));
        }

        return result;
    }

    bool get_transaction(const uint256& txid, WalletTx& wtx) override {
        auto txs = wallet_.get_transactions(10000, 0);
        for (const auto& dtx : txs) {
            if (dtx.txid == txid) {
                wtx.txid = dtx.txid;
                wtx.amount = dtx.amount;
                wtx.fee = dtx.fee;
                wtx.confirmations = dtx.confirmations;
                wtx.time = dtx.timestamp;
                wtx.address = dtx.address;
                wtx.label = dtx.label;
                wtx.is_send = dtx.is_send;
                wtx.is_coinbase = dtx.is_coinbase;
                return true;
            }
        }
        return false;
    }

    size_t get_tx_count() override {
        auto txs = wallet_.get_transactions(10000, 0);
        return txs.size();
    }

    // ---- Sending -----------------------------------------------------------

    SendResult send(const std::string& address, Amount amount,
                    const std::string& /*comment*/) override {
        SendResult result;

        auto wallet_result = wallet_.send_to_address(address, amount);
        result.success = wallet_result.success;
        result.error = wallet_result.error;

        if (wallet_result.success) {
            result.txid = wallet_result.tx.get_txid();
            // Calculate fee from inputs - outputs
            result.fee = 0;  // Would need UTXO lookup for exact fee
        }

        return result;
    }

    SendResult create_transaction(const std::string& address,
                                   Amount amount) override {
        // Same as send for now -- wallet doesn't have a separate
        // create-without-broadcast API
        return send(address, amount, "");
    }

    // ---- UTXOs -------------------------------------------------------------

    std::vector<Coin> list_unspent(int min_conf, int max_conf) override {
        auto wallet_coins = wallet_.list_unspent();
        std::vector<Coin> result;
        result.reserve(wallet_coins.size());

        uint64_t chain_height = chain_.height();

        for (const auto& wc : wallet_coins) {
            int conf = static_cast<int>(chain_height - wc.height + 1);
            if (conf < min_conf || conf > max_conf) continue;

            Coin coin;
            coin.txid = wc.txid;
            coin.vout = wc.vout;
            coin.value = wc.value;
            coin.confirmations = conf;
            coin.is_coinbase = wc.is_coinbase;
            // Address would need pubkey-to-address conversion
            coin.address = "";
            result.push_back(std::move(coin));
        }

        return result;
    }

    size_t utxo_count() override {
        return wallet_.list_unspent().size();
    }

    // ---- Encryption --------------------------------------------------------

    bool is_encrypted() override {
        return wallet_.is_encrypted();
    }

    bool is_locked() override {
        return wallet_.is_locked();
    }

    bool encrypt(const std::string& passphrase) override {
        return wallet_.encrypt_wallet(passphrase);
    }

    bool unlock(const std::string& passphrase, int timeout_seconds) override {
        return wallet_.walletpassphrase(passphrase, timeout_seconds);
    }

    bool lock() override {
        wallet_.walletlock();
        return true;
    }

    bool change_passphrase(const std::string& /*old_passphrase*/,
                            const std::string& /*new_passphrase*/) override {
        // Would need: decrypt with old, re-encrypt with new
        return false;
    }

    // ---- Labels ------------------------------------------------------------

    void set_label(const std::string& address,
                    const std::string& label) override {
        wallet_.set_label(address, label);
    }

    std::string get_label(const std::string& address) override {
        return wallet_.get_label(address);
    }

    std::vector<std::string> get_addresses_by_label(
        const std::string& label) override {
        return wallet_.get_addresses_by_label(label);
    }

    // ---- Import / export ---------------------------------------------------

    bool import_privkey(const std::string& privkey_hex) override {
        if (privkey_hex.size() != 64) return false;

        std::array<uint8_t, 32> key{};
        for (size_t i = 0; i < 32; ++i) {
            unsigned int byte_val = 0;
            char hi = privkey_hex[i * 2];
            char lo = privkey_hex[i * 2 + 1];

            auto hex_val = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
                return -1;
            };

            int h = hex_val(hi);
            int l = hex_val(lo);
            if (h < 0 || l < 0) return false;

            byte_val = static_cast<unsigned int>(h * 16 + l);
            key[i] = static_cast<uint8_t>(byte_val);
        }

        return wallet_.import_privkey(key);
    }

    bool backup(const std::string& /*path*/) override {
        // Wallet backup would copy the wallet.dat file
        return false;
    }

    // ---- Message signing ---------------------------------------------------

    std::string sign_message(const std::string& address,
                              const std::string& message) override {
        auto sig = wallet_.sign_message(address, message);
        if (sig.empty()) return "";

        // Convert to hex
        std::string hex;
        hex.reserve(sig.size() * 2);
        for (uint8_t b : sig) {
            static const char* digits = "0123456789abcdef";
            hex.push_back(digits[b >> 4]);
            hex.push_back(digits[b & 0xf]);
        }
        return hex;
    }

    bool verify_message(const std::string& /*address*/,
                         const std::string& /*signature*/,
                         const std::string& /*message*/) override {
        // Would need Ed25519 verify with address -> pubkey mapping
        return false;
    }

    // ---- Notifications -----------------------------------------------------

    void register_tx_callback(TxNotifyCallback cb) override {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        tx_callbacks_.push_back(std::move(cb));
    }

    void register_balance_callback(BalanceChangedCallback cb) override {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        balance_callbacks_.push_back(std::move(cb));
    }

    void register_address_callback(AddressCallback cb) override {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        address_callbacks_.push_back(std::move(cb));
    }

    // ---- Wallet info -------------------------------------------------------

    std::string get_wallet_path() override {
        return "";  // Would need WalletDB path accessor
    }

    int get_wallet_version() override {
        return 1;
    }

private:
    Wallet& wallet_;
    ChainState& chain_;

    std::mutex cb_mutex_;
    std::vector<TxNotifyCallback> tx_callbacks_;
    std::vector<BalanceChangedCallback> balance_callbacks_;
    std::vector<AddressCallback> address_callbacks_;
};

// ============================================================================
// Factory function
// ============================================================================

std::unique_ptr<WalletInterface> make_wallet(Wallet& wallet,
                                              ChainState& chain) {
    return std::make_unique<WalletImpl>(wallet, chain);
}

} // namespace flow::interfaces
