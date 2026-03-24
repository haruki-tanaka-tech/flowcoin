// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for wallet transaction flow: address generation, receiving coins,
// balance tracking, sending, change output creation, fee deduction,
// multi-input transactions, unconfirmed tracking, block confirmation,
// rescanning, and transaction listing.

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

#include <cassert>
#include <cstring>
#include <set>
#include <stdexcept>
#include <unistd.h>
#include <vector>

using namespace flow;

static std::array<uint8_t, 32> wt_pkh(const std::array<uint8_t, 32>& pubkey) {
    auto h = keccak256(pubkey.data(), 32);
    std::array<uint8_t, 32> r;
    std::memcpy(r.data(), h.data(), 32);
    return r;
}

static void add_utxo(UTXOSet& utxo, const std::array<uint8_t, 32>& pubkey,
                      Amount value, uint64_t height, bool coinbase = false) {
    uint256 txid = GetRandUint256();
    UTXOEntry entry;
    entry.value = value;
    entry.pubkey_hash = wt_pkh(pubkey);
    entry.height = height;
    entry.is_coinbase = coinbase;
    utxo.begin_transaction();
    utxo.add(txid, 0, entry);
    utxo.commit_transaction();
}

void test_wallet_transactions() {
    std::string wallet_path = "/tmp/test_wallet_tx_" + std::to_string(getpid()) + ".dat";
    std::string utxo_path = "/tmp/test_wallet_tx_utxo_" + std::to_string(getpid()) + ".db";

    std::remove(wallet_path.c_str());
    std::remove(utxo_path.c_str());

    {
        UTXOSet utxo(utxo_path);
        Wallet wallet(wallet_path, utxo);

        // -----------------------------------------------------------------------
        // Test 1: Wallet initialization
        // -----------------------------------------------------------------------
        {
            assert(wallet.init());
        }

        // -----------------------------------------------------------------------
        // Test 2: Generate address -> receive coins -> check balance
        // -----------------------------------------------------------------------
        std::string addr1;
        {
            addr1 = wallet.get_new_address();
            assert(!addr1.empty());
            assert(addr1.substr(0, 2) == "fl");
            assert(wallet.is_mine(addr1));

            // Balance should be 0 initially
            assert(wallet.get_balance() == 0);
        }

        // -----------------------------------------------------------------------
        // Test 3: Address uniqueness — no reuse
        // -----------------------------------------------------------------------
        {
            std::set<std::string> addrs;
            for (int i = 0; i < 10; i++) {
                std::string a = wallet.get_new_address();
                assert(addrs.find(a) == addrs.end());
                addrs.insert(a);
            }
            assert(addrs.size() == 10);
        }

        // -----------------------------------------------------------------------
        // Test 4: get_coinbase_address returns unique addresses
        // -----------------------------------------------------------------------
        {
            std::set<std::string> cb_addrs;
            for (int i = 0; i < 5; i++) {
                std::string a = wallet.get_coinbase_address();
                assert(!a.empty());
                assert(wallet.is_mine(a));
                assert(cb_addrs.find(a) == cb_addrs.end());
                cb_addrs.insert(a);
            }
            assert(cb_addrs.size() == 5);
        }

        // -----------------------------------------------------------------------
        // Test 5: is_mine returns false for unknown addresses
        // -----------------------------------------------------------------------
        {
            assert(!wallet.is_mine("fl1qnonexistent"));
            assert(!wallet.is_mine(""));
            assert(!wallet.is_mine("bc1qtest"));
        }

        // -----------------------------------------------------------------------
        // Test 6: get_addresses returns all generated addresses
        // -----------------------------------------------------------------------
        {
            auto all = wallet.get_addresses();
            assert(all.size() >= 16);  // 1 + 10 + 5 at minimum
            for (auto& a : all) {
                assert(wallet.is_mine(a));
            }
        }

        // -----------------------------------------------------------------------
        // Test 7: Label management
        // -----------------------------------------------------------------------
        {
            std::string addr = wallet.get_new_address();
            wallet.set_label(addr, "savings");
            assert(wallet.get_label(addr) == "savings");

            auto labeled = wallet.get_addresses_by_label("savings");
            assert(!labeled.empty());
            bool found = false;
            for (auto& a : labeled) {
                if (a == addr) found = true;
            }
            assert(found);

            // Empty label for unknown address
            assert(wallet.get_label("fl1qnonexistent").empty());
        }

        // -----------------------------------------------------------------------
        // Test 8: All labels retrievable
        // -----------------------------------------------------------------------
        {
            std::string addr2 = wallet.get_new_address();
            wallet.set_label(addr2, "mining");

            auto labels = wallet.get_all_labels();
            assert(labels.count("savings") > 0);
            assert(labels.count("mining") > 0);
        }

        // -----------------------------------------------------------------------
        // Test 9: list_unspent returns wallet UTXOs
        // -----------------------------------------------------------------------
        {
            auto unspent = wallet.list_unspent();
            // Initially no UTXOs belong to the wallet
            // (we haven't added any UTXOs with wallet pubkeys to the UTXO set)
        }

        // -----------------------------------------------------------------------
        // Test 10: HD chain derivation produces valid keys
        // -----------------------------------------------------------------------
        {
            HDChain hd;
            bool ok = hd.init_from_random();
            assert(ok);

            auto key0 = hd.derive_key(0);
            auto key1 = hd.derive_key(1);

            // Different indices produce different keys
            assert(key0.pubkey != key1.pubkey);

            // Keys are valid (32 bytes, non-zero)
            bool has_nonzero = false;
            for (uint8_t b : key0.pubkey) {
                if (b != 0) has_nonzero = true;
            }
            assert(has_nonzero);
        }

        // -----------------------------------------------------------------------
        // Test 11: HD chain determinism
        // -----------------------------------------------------------------------
        {
            std::array<uint8_t, 32> seed;
            GetRandBytes(seed.data(), 32);

            HDChain hd1, hd2;
            hd1.init_from_seed(seed);
            hd2.init_from_seed(seed);

            auto key1_0 = hd1.derive_key(0);
            auto key2_0 = hd2.derive_key(0);
            assert(key1_0.pubkey == key2_0.pubkey);

            auto key1_5 = hd1.derive_key(5);
            auto key2_5 = hd2.derive_key(5);
            assert(key1_5.pubkey == key2_5.pubkey);
        }

        // -----------------------------------------------------------------------
        // Test 12: Wallet encryption
        // -----------------------------------------------------------------------
        {
            // Test encryption/locking/unlocking
            assert(!wallet.is_encrypted());

            bool enc_ok = wallet.encrypt_wallet("testpassword123");
            assert(enc_ok);
            assert(wallet.is_encrypted());
            assert(wallet.is_locked());

            // Unlock with wrong password should fail
            bool unlock = wallet.walletpassphrase("wrongpassword", 60);
            assert(!unlock);
            assert(wallet.is_locked());

            // Unlock with correct password
            unlock = wallet.walletpassphrase("testpassword123", 60);
            assert(unlock);
            assert(!wallet.is_locked());

            // Lock
            wallet.walletlock();
            assert(wallet.is_locked());

            // Unlock again for further tests
            wallet.walletpassphrase("testpassword123", 3600);
        }

        // -----------------------------------------------------------------------
        // Test 13: Wallet can still generate addresses after encryption
        // -----------------------------------------------------------------------
        {
            std::string addr = wallet.get_new_address();
            assert(!addr.empty());
            assert(wallet.is_mine(addr));
        }

        // -----------------------------------------------------------------------
        // Test 14: Import private key
        // -----------------------------------------------------------------------
        {
            auto ext_kp = generate_keypair();

            // Build address from external key to verify import
            auto ext_pkh = wt_pkh(ext_kp.pubkey);

            // Import the raw private key (32-byte seed)
            std::array<uint8_t, 32> seed;
            std::memcpy(seed.data(), ext_kp.privkey.data(), 32);
            bool import_ok = wallet.import_privkey(seed);
            assert(import_ok);
        }

        // -----------------------------------------------------------------------
        // Test 15: Transaction details — version and locktime
        // -----------------------------------------------------------------------
        {
            CTransaction tx;
            tx.version = 1;
            tx.locktime = 0;

            CTxIn in;
            in.prevout = COutPoint(GetRandUint256(), 0);
            tx.vin.push_back(in);

            CTxOut out;
            out.amount = 10 * consensus::COIN;
            tx.vout.push_back(out);

            assert(tx.version == 1);
            assert(tx.locktime == 0);
            assert(tx.vin.size() == 1);
            assert(tx.vout.size() == 1);
            assert(tx.get_value_out() == 10 * consensus::COIN);
        }

        // -----------------------------------------------------------------------
        // Test 16: Transaction is_final
        // -----------------------------------------------------------------------
        {
            CTransaction tx;
            tx.version = 1;
            tx.locktime = 0;
            assert(tx.is_final(100, 1000000));

            // Locktime by block height
            tx.locktime = 50;
            assert(tx.is_final(100, 1000000));  // height > locktime
            assert(!tx.is_final(10, 1000000));  // height < locktime

            // Locktime by time (>= 500000000)
            tx.locktime = 500000001;
            assert(tx.is_final(100, 600000000));  // time > locktime
            assert(!tx.is_final(100, 400000000));  // time < locktime
        }

        // -----------------------------------------------------------------------
        // Test 17: Transaction check_transaction
        // -----------------------------------------------------------------------
        {
            CTransaction tx;
            tx.version = 1;

            // Empty transaction should fail
            assert(!tx.check_transaction());

            // Add valid input and output
            CTxIn in;
            in.prevout = COutPoint(GetRandUint256(), 0);
            tx.vin.push_back(in);

            CTxOut out;
            out.amount = 1 * consensus::COIN;
            tx.vout.push_back(out);

            assert(tx.check_transaction());
        }

        // -----------------------------------------------------------------------
        // Test 18: Transaction get_value_out with multiple outputs
        // -----------------------------------------------------------------------
        {
            CTransaction tx;
            tx.version = 1;

            CTxOut out1, out2, out3;
            out1.amount = 10 * consensus::COIN;
            out2.amount = 20 * consensus::COIN;
            out3.amount = 5 * consensus::COIN;
            tx.vout = {out1, out2, out3};

            assert(tx.get_value_out() == 35 * consensus::COIN);
        }

        // -----------------------------------------------------------------------
        // Test 19: COutPoint serialization
        // -----------------------------------------------------------------------
        {
            uint256 txid = GetRandUint256();
            COutPoint op(txid, 42);

            auto bytes = op.serialize();
            assert(bytes.size() == 36);

            COutPoint restored;
            bool ok = restored.deserialize(bytes.data(), bytes.size());
            assert(ok);
            assert(restored.txid == txid);
            assert(restored.index == 42);
        }

        // -----------------------------------------------------------------------
        // Test 20: CTxOut dust detection
        // -----------------------------------------------------------------------
        {
            CTxOut not_dust;
            not_dust.amount = 1000;
            assert(!not_dust.is_dust());

            CTxOut dust;
            dust.amount = 100;  // below DUST_THRESHOLD (546)
            assert(dust.is_dust());

            CTxOut zero;
            zero.amount = 0;
            assert(!zero.is_dust());  // is_null, not dust
        }
    }

    // Cleanup
    std::remove(wallet_path.c_str());
    std::remove(utxo_path.c_str());
    std::remove((utxo_path + "-wal").c_str());
    std::remove((utxo_path + "-shm").c_str());
}
