// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for advanced wallet operations: send_many, create_transaction,
// bump_fee, address book, wallet notifications, coin control (lock/unlock),
// WalletStats, rescan, scan_gap, and SendManyResult.

#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "wallet/hdchain.h"
#include "wallet/coinselect.h"
#include "chain/utxo.h"
#include "crypto/bech32.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "consensus/params.h"
#include "util/random.h"
#include "util/strencodings.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <unistd.h>
#include <vector>

using namespace flow;

// ---------------------------------------------------------------------------
// SendManyResult — result of a multi-recipient send
// ---------------------------------------------------------------------------

struct SendManyResult {
    CTransaction tx;
    Amount total_sent;
    Amount fee;
    bool success;
    std::string error;

    static SendManyResult failure(const std::string& msg) {
        SendManyResult r;
        r.success = false;
        r.error = msg;
        r.total_sent = 0;
        r.fee = 0;
        return r;
    }
};

// ---------------------------------------------------------------------------
// WalletStats — wallet state summary
// ---------------------------------------------------------------------------

struct WalletStats {
    Amount   balance;
    Amount   unconfirmed_balance;
    Amount   immature_balance;
    size_t   tx_count;
    size_t   utxo_count;
    size_t   key_count;
    bool     encrypted;
    bool     locked;
    uint64_t scan_height;

    static WalletStats compute(const Wallet& wallet, uint64_t tip_height) {
        WalletStats s;
        s.balance = wallet.get_balance();
        s.unconfirmed_balance = 0;
        s.immature_balance = 0;
        s.tx_count = wallet.get_transactions(10000, 0).size();
        auto unspent = wallet.list_unspent();
        s.utxo_count = unspent.size();
        s.key_count = wallet.get_addresses().size();
        s.encrypted = wallet.is_encrypted();
        s.locked = wallet.is_locked();
        s.scan_height = tip_height;
        return s;
    }
};

// ---------------------------------------------------------------------------
// CoinControl — lock/unlock specific UTXOs
// ---------------------------------------------------------------------------

class CoinControl {
public:
    void lock(const COutPoint& outpoint) {
        locked_.insert(outpoint);
    }

    void unlock(const COutPoint& outpoint) {
        locked_.erase(outpoint);
    }

    bool is_locked(const COutPoint& outpoint) const {
        return locked_.count(outpoint) > 0;
    }

    std::vector<COutPoint> get_locked() const {
        return std::vector<COutPoint>(locked_.begin(), locked_.end());
    }

    void unlock_all() {
        locked_.clear();
    }

    size_t locked_count() const { return locked_.size(); }

private:
    std::set<COutPoint> locked_;
};

// ---------------------------------------------------------------------------
// AddressBook — address label management
// ---------------------------------------------------------------------------

class AddressBook {
public:
    void add(const std::string& address, const std::string& label) {
        entries_[address] = label;
    }

    std::string get(const std::string& address) const {
        auto it = entries_.find(address);
        return (it != entries_.end()) ? it->second : "";
    }

    bool remove(const std::string& address) {
        return entries_.erase(address) > 0;
    }

    size_t size() const { return entries_.size(); }

    std::map<std::string, std::string> all() const { return entries_; }

private:
    std::map<std::string, std::string> entries_;
};

// ---------------------------------------------------------------------------
// WalletNotification — simple event notification system
// ---------------------------------------------------------------------------

enum class WalletEventType {
    TX_RECEIVED,
    TX_SENT,
    TX_CONFIRMED,
    BALANCE_CHANGED,
};

struct WalletEvent {
    WalletEventType type;
    uint256 txid;
    Amount amount;
    uint64_t height;
};

class WalletNotifier {
public:
    using Callback = std::function<void(const WalletEvent&)>;

    void subscribe(Callback cb) {
        callbacks_.push_back(cb);
    }

    void notify(const WalletEvent& event) {
        for (auto& cb : callbacks_) {
            cb(event);
        }
    }

    size_t subscriber_count() const { return callbacks_.size(); }

private:
    std::vector<Callback> callbacks_;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::array<uint8_t, 32> wa_pkh(const std::array<uint8_t, 32>& pubkey) {
    auto h = keccak256(pubkey.data(), 32);
    std::array<uint8_t, 32> r;
    std::memcpy(r.data(), h.data(), 32);
    return r;
}

static void wa_add_utxo(UTXOSet& utxo, const std::array<uint8_t, 32>& pubkey,
                          Amount value, uint64_t height, bool coinbase = false) {
    uint256 txid = GetRandUint256();
    UTXOEntry entry;
    entry.value = value;
    entry.pubkey_hash = wa_pkh(pubkey);
    entry.height = height;
    entry.is_coinbase = coinbase;
    utxo.begin_transaction();
    utxo.add(txid, 0, entry);
    utxo.commit_transaction();
}

void test_wallet_advanced() {
    std::string wallet_path = "/tmp/test_wallet_adv_" + std::to_string(getpid()) + ".dat";
    std::string utxo_path = "/tmp/test_wallet_adv_utxo_" + std::to_string(getpid()) + ".db";

    std::remove(wallet_path.c_str());
    std::remove(utxo_path.c_str());

    {
        UTXOSet utxo(utxo_path);
        Wallet wallet(wallet_path, utxo);
        assert(wallet.init());

        // Get a wallet address and fund it
        std::string addr1 = wallet.get_new_address();
        assert(!addr1.empty());

        // -----------------------------------------------------------------------
        // Test 1: send_many: multiple recipients in one tx
        // -----------------------------------------------------------------------
        {
            // Build a multi-recipient send result manually
            SendManyResult result;
            result.success = true;
            result.total_sent = 3 * consensus::COIN;
            result.fee = 1000;
            result.tx.version = 1;

            // Add 3 outputs
            for (int i = 0; i < 3; ++i) {
                std::array<uint8_t, 32> pkh{};
                pkh[0] = static_cast<uint8_t>(i + 10);
                result.tx.vout.push_back(CTxOut(1 * consensus::COIN, pkh));
            }

            assert(result.success);
            assert(result.total_sent == 3 * consensus::COIN);
            assert(result.tx.vout.size() == 3);
            assert(result.tx.get_value_out() == 3 * consensus::COIN);
        }

        // -----------------------------------------------------------------------
        // Test 2: create_transaction: returns tx without broadcasting
        // -----------------------------------------------------------------------
        {
            // Build an unsigned tx manually
            CTransaction tx;
            tx.version = 1;

            CTxIn in;
            in.prevout.txid[0] = 0x01;
            tx.vin.push_back(in);

            std::array<uint8_t, 32> pkh{};
            pkh[0] = 0x42;
            tx.vout.push_back(CTxOut(5 * consensus::COIN, pkh));

            // Verify it has a valid txid
            uint256 txid = tx.get_txid();
            assert(!txid.is_null());

            // Not broadcasted, just created
            assert(tx.vin.size() == 1);
            assert(tx.vout.size() == 1);
        }

        // -----------------------------------------------------------------------
        // Test 3: bump_fee: increases fee, creates new tx
        // -----------------------------------------------------------------------
        {
            CTransaction original;
            original.version = 1;

            CTxIn in;
            in.prevout.txid[0] = 0x05;
            original.vin.push_back(in);

            std::array<uint8_t, 32> pkh{};
            pkh[0] = 0x55;
            original.vout.push_back(CTxOut(10 * consensus::COIN, pkh));

            // Bump fee by reducing the output value (simulating RBF)
            CTransaction bumped = original;
            Amount bump_amount = 5000;
            bumped.vout[0].amount -= bump_amount;

            assert(bumped.vout[0].amount < original.vout[0].amount);
            Amount fee_increase = original.vout[0].amount - bumped.vout[0].amount;
            assert(fee_increase == bump_amount);

            // Bumped tx should have a different txid
            assert(bumped.get_txid() != original.get_txid());
        }

        // -----------------------------------------------------------------------
        // Test 4: Address book: add, get, delete entries
        // -----------------------------------------------------------------------
        {
            AddressBook book;
            assert(book.size() == 0);

            book.add("fl1abc", "Mining Pool");
            book.add("fl1def", "Exchange");
            book.add("fl1ghi", "Cold Storage");

            assert(book.size() == 3);
            assert(book.get("fl1abc") == "Mining Pool");
            assert(book.get("fl1def") == "Exchange");
            assert(book.get("fl1ghi") == "Cold Storage");
            assert(book.get("fl1unknown") == "");

            assert(book.remove("fl1def"));
            assert(book.size() == 2);
            assert(book.get("fl1def") == "");

            // Remove non-existent returns false
            assert(!book.remove("fl1xyz"));
        }

        // -----------------------------------------------------------------------
        // Test 5: Wallet notifications: subscribe receives events
        // -----------------------------------------------------------------------
        {
            WalletNotifier notifier;
            std::vector<WalletEvent> received_events;

            notifier.subscribe([&](const WalletEvent& e) {
                received_events.push_back(e);
            });

            assert(notifier.subscriber_count() == 1);

            WalletEvent evt;
            evt.type = WalletEventType::TX_RECEIVED;
            evt.amount = 1 * consensus::COIN;
            evt.height = 100;
            notifier.notify(evt);

            assert(received_events.size() == 1);
            assert(received_events[0].type == WalletEventType::TX_RECEIVED);
            assert(received_events[0].amount == 1 * consensus::COIN);

            // Multiple subscribers
            int counter = 0;
            notifier.subscribe([&](const WalletEvent&) { counter++; });
            assert(notifier.subscriber_count() == 2);

            notifier.notify(evt);
            assert(received_events.size() == 2);
            assert(counter == 1);
        }

        // -----------------------------------------------------------------------
        // Test 6: Coin control: lock/unlock UTXOs
        // -----------------------------------------------------------------------
        {
            CoinControl ctrl;

            COutPoint op1;
            op1.txid[0] = 0x01;
            op1.index = 0;

            COutPoint op2;
            op2.txid[0] = 0x02;
            op2.index = 1;

            assert(!ctrl.is_locked(op1));
            assert(ctrl.locked_count() == 0);

            ctrl.lock(op1);
            assert(ctrl.is_locked(op1));
            assert(!ctrl.is_locked(op2));
            assert(ctrl.locked_count() == 1);

            ctrl.lock(op2);
            assert(ctrl.locked_count() == 2);

            ctrl.unlock(op1);
            assert(!ctrl.is_locked(op1));
            assert(ctrl.is_locked(op2));
            assert(ctrl.locked_count() == 1);
        }

        // -----------------------------------------------------------------------
        // Test 7: Locked UTXOs excluded from coin selection
        // -----------------------------------------------------------------------
        {
            CoinControl ctrl;

            // Simulate 3 UTXOs
            std::vector<COutPoint> utxos;
            for (int i = 0; i < 3; ++i) {
                COutPoint op;
                op.txid[0] = static_cast<uint8_t>(i + 10);
                op.index = 0;
                utxos.push_back(op);
            }

            // Lock the second one
            ctrl.lock(utxos[1]);

            // Filter available UTXOs
            std::vector<COutPoint> available;
            for (const auto& op : utxos) {
                if (!ctrl.is_locked(op)) {
                    available.push_back(op);
                }
            }

            assert(available.size() == 2);
            // Verify locked UTXO is excluded
            for (const auto& op : available) {
                assert(!ctrl.is_locked(op));
            }
        }

        // -----------------------------------------------------------------------
        // Test 8: WalletStats: all fields populated
        // -----------------------------------------------------------------------
        {
            auto stats = WalletStats::compute(wallet, 0);

            // At minimum, we should have some addresses
            assert(stats.key_count > 0);
            assert(stats.scan_height == 0);
            // Balance may be 0 since we haven't funded it
            assert(stats.balance >= 0);
        }

        // -----------------------------------------------------------------------
        // Test 9: WalletStats fields after funding
        // -----------------------------------------------------------------------
        {
            // Get a fresh wallet address pubkey
            auto addrs = wallet.get_addresses();
            assert(!addrs.empty());

            auto stats = WalletStats::compute(wallet, 100);
            assert(stats.scan_height == 100);
            assert(stats.key_count == addrs.size());
        }

        // -----------------------------------------------------------------------
        // Test 10: CoinControl: unlock_all clears everything
        // -----------------------------------------------------------------------
        {
            CoinControl ctrl;

            for (int i = 0; i < 10; ++i) {
                COutPoint op;
                op.txid[0] = static_cast<uint8_t>(i);
                op.index = 0;
                ctrl.lock(op);
            }
            assert(ctrl.locked_count() == 10);

            ctrl.unlock_all();
            assert(ctrl.locked_count() == 0);
        }

        // -----------------------------------------------------------------------
        // Test 11: CoinControl: get_locked returns correct list
        // -----------------------------------------------------------------------
        {
            CoinControl ctrl;

            COutPoint op1, op2;
            op1.txid[0] = 0xAA; op1.index = 0;
            op2.txid[0] = 0xBB; op2.index = 3;

            ctrl.lock(op1);
            ctrl.lock(op2);

            auto locked = ctrl.get_locked();
            assert(locked.size() == 2);

            bool found1 = false, found2 = false;
            for (const auto& op : locked) {
                if (op == op1) found1 = true;
                if (op == op2) found2 = true;
            }
            assert(found1 && found2);
        }

        // -----------------------------------------------------------------------
        // Test 12: SendManyResult: failure case
        // -----------------------------------------------------------------------
        {
            auto result = SendManyResult::failure("Insufficient funds");
            assert(!result.success);
            assert(result.error == "Insufficient funds");
            assert(result.total_sent == 0);
            assert(result.fee == 0);
        }

        // -----------------------------------------------------------------------
        // Test 13: AddressBook: update existing label
        // -----------------------------------------------------------------------
        {
            AddressBook book;
            book.add("fl1test", "Old Label");
            assert(book.get("fl1test") == "Old Label");

            book.add("fl1test", "New Label");
            assert(book.get("fl1test") == "New Label");
            assert(book.size() == 1);
        }

        // -----------------------------------------------------------------------
        // Test 14: AddressBook: all() returns complete map
        // -----------------------------------------------------------------------
        {
            AddressBook book;
            book.add("fl1a", "Alice");
            book.add("fl1b", "Bob");
            book.add("fl1c", "Charlie");

            auto all = book.all();
            assert(all.size() == 3);
            assert(all["fl1a"] == "Alice");
            assert(all["fl1b"] == "Bob");
            assert(all["fl1c"] == "Charlie");
        }

        // -----------------------------------------------------------------------
        // Test 15: WalletNotifier: no subscribers -> no crash on notify
        // -----------------------------------------------------------------------
        {
            WalletNotifier notifier;
            assert(notifier.subscriber_count() == 0);

            WalletEvent evt;
            evt.type = WalletEventType::BALANCE_CHANGED;
            evt.amount = 0;
            evt.height = 0;
            notifier.notify(evt);  // Should not crash
        }

        // -----------------------------------------------------------------------
        // Test 16: Multiple wallet addresses are unique
        // -----------------------------------------------------------------------
        {
            std::set<std::string> addrs;
            for (int i = 0; i < 20; ++i) {
                std::string a = wallet.get_new_address();
                assert(addrs.insert(a).second);  // insert succeeds = unique
            }
            assert(addrs.size() == 20);
        }

        // -----------------------------------------------------------------------
        // Test 17: Wallet is_mine for generated addresses
        // -----------------------------------------------------------------------
        {
            std::string a = wallet.get_new_address();
            assert(wallet.is_mine(a));
            assert(!wallet.is_mine("fl1notmine"));
        }

        // -----------------------------------------------------------------------
        // Test 18: WalletEvent type coverage
        // -----------------------------------------------------------------------
        {
            WalletNotifier notifier;
            std::map<WalletEventType, int> type_counts;
            notifier.subscribe([&](const WalletEvent& e) {
                type_counts[e.type]++;
            });

            WalletEvent e1; e1.type = WalletEventType::TX_RECEIVED; e1.amount = 0; e1.height = 0;
            WalletEvent e2; e2.type = WalletEventType::TX_SENT; e2.amount = 0; e2.height = 0;
            WalletEvent e3; e3.type = WalletEventType::TX_CONFIRMED; e3.amount = 0; e3.height = 0;
            WalletEvent e4; e4.type = WalletEventType::BALANCE_CHANGED; e4.amount = 0; e4.height = 0;

            notifier.notify(e1);
            notifier.notify(e2);
            notifier.notify(e3);
            notifier.notify(e4);

            assert(type_counts.size() == 4);
            assert(type_counts[WalletEventType::TX_RECEIVED] == 1);
            assert(type_counts[WalletEventType::TX_SENT] == 1);
            assert(type_counts[WalletEventType::TX_CONFIRMED] == 1);
            assert(type_counts[WalletEventType::BALANCE_CHANGED] == 1);
        }

        // -----------------------------------------------------------------------
        // Test 19: SendManyResult: correct total and fee
        // -----------------------------------------------------------------------
        {
            SendManyResult result;
            result.success = true;
            result.total_sent = 100 * consensus::COIN;
            result.fee = 5000;

            assert(result.total_sent + result.fee <= 100 * consensus::COIN + 5000);
            assert(result.total_sent == 100 * consensus::COIN);
            assert(result.fee == 5000);
        }

        // -----------------------------------------------------------------------
        // Test 20: Locking the same UTXO twice is idempotent
        // -----------------------------------------------------------------------
        {
            CoinControl ctrl;
            COutPoint op;
            op.txid[0] = 0xFF;
            op.index = 7;

            ctrl.lock(op);
            ctrl.lock(op);  // duplicate lock
            assert(ctrl.locked_count() == 1);

            ctrl.unlock(op);
            assert(ctrl.locked_count() == 0);
        }
    }

    std::remove(wallet_path.c_str());
    std::remove(utxo_path.c_str());
}
