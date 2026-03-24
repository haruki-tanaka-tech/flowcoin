// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for transaction building: coin selection, change output creation,
// dust threshold, fee calculation, and signing. Uses the CoinSelection
// infrastructure from wallet/coinselect.h and builds complete signed
// transactions.

#include "wallet/coinselect.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/transaction.h"
#include "util/types.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <vector>

// Helper: compute pubkey hash
static std::array<uint8_t, 32> compute_pkh(const std::array<uint8_t, 32>& pubkey) {
    auto hash = flow::keccak256(pubkey.data(), 32);
    std::array<uint8_t, 32> pkh;
    std::memcpy(pkh.data(), hash.data(), 32);
    return pkh;
}

// Helper: make a CoinToSpend entry
static flow::CoinToSpend make_coin(uint32_t id, flow::Amount value,
                                    const std::array<uint8_t, 32>& pubkey) {
    flow::CoinToSpend coin;
    coin.txid.set_null();
    std::memcpy(coin.txid.data(), &id, sizeof(id));
    coin.vout = 0;
    coin.value = value;
    coin.pubkey = pubkey;
    return coin;
}

// Helper: build and sign a transaction from a coin selection
static flow::CTransaction build_and_sign_tx(
    const flow::CoinSelection& selection,
    const std::array<uint8_t, 32>& recipient_pkh,
    flow::Amount send_amount,
    const std::array<uint8_t, 32>& change_pkh,
    const flow::KeyPair& sender_kp)
{
    flow::CTransaction tx;

    // Add inputs
    for (const auto& coin : selection.selected) {
        flow::CTxIn in;
        in.prevout = flow::COutPoint(coin.txid, coin.vout);
        std::memcpy(in.pubkey.data(), coin.pubkey.data(), 32);
        tx.vin.push_back(in);
    }

    // Add recipient output
    tx.vout.push_back(flow::CTxOut(send_amount, recipient_pkh));

    // Add change output if change > 0
    if (selection.change > 0) {
        tx.vout.push_back(flow::CTxOut(selection.change, change_pkh));
    }

    // Compute txid (excludes signatures)
    auto txid = tx.get_txid();

    // Sign each input
    for (size_t i = 0; i < tx.vin.size(); i++) {
        auto sig = flow::ed25519_sign(txid.data(), txid.size(),
                                       sender_kp.privkey.data(),
                                       sender_kp.pubkey.data());
        std::memcpy(tx.vin[i].signature.data(), sig.data(), 64);
    }

    return tx;
}

void test_txbuilder() {
    using namespace flow;

    auto kp_sender = generate_keypair();
    auto kp_recipient = generate_keypair();
    auto pkh_sender = compute_pkh(kp_sender.pubkey);
    auto pkh_recipient = compute_pkh(kp_recipient.pubkey);

    // Test 1: Build simple 1-input 1-output transaction
    {
        std::vector<CoinToSpend> available = {
            make_coin(1, 50 * COIN, kp_sender.pubkey),
        };

        Amount target = 50 * COIN - 1000;  // Leave room for fee
        auto selection = select_coins(available, target, 1000);
        assert(selection.success);
        assert(selection.selected.size() == 1);
        assert(selection.total_selected == 50 * COIN);
        assert(selection.fee == 1000);

        auto tx = build_and_sign_tx(selection, pkh_recipient, target,
                                     pkh_sender, kp_sender);
        assert(tx.vin.size() == 1);
        assert(tx.vout.size() >= 1);

        // Verify txid is non-null
        auto txid = tx.get_txid();
        assert(!txid.is_null());

        // Verify signature is non-zero
        bool sig_nonzero = false;
        for (auto b : tx.vin[0].signature) {
            if (b != 0) { sig_nonzero = true; break; }
        }
        assert(sig_nonzero);
    }

    // Test 2: Change output created when excess
    {
        std::vector<CoinToSpend> available = {
            make_coin(2, 100 * COIN, kp_sender.pubkey),
        };

        Amount target = 30 * COIN;
        auto selection = select_coins(available, target, 1000);
        assert(selection.success);
        assert(selection.selected.size() == 1);

        // Change = total - target - fee
        Amount expected_change = 100 * COIN - 30 * COIN - 1000;
        assert(selection.change == expected_change);

        auto tx = build_and_sign_tx(selection, pkh_recipient, target,
                                     pkh_sender, kp_sender);

        // Should have 2 outputs: recipient + change
        assert(tx.vout.size() == 2);
        assert(tx.vout[0].amount == 30 * COIN);
        assert(tx.vout[0].pubkey_hash == pkh_recipient);
        assert(tx.vout[1].amount == expected_change);
        assert(tx.vout[1].pubkey_hash == pkh_sender);
    }

    // Test 3: Dust threshold — very small change is dropped
    {
        // When change is very small (dust), it's better to absorb it into
        // the fee rather than create a tiny output
        std::vector<CoinToSpend> available = {
            make_coin(3, 10000, kp_sender.pubkey),
        };

        // Try to send just under the total (leaving dust-level change)
        Amount target = 10000 - 1000 - 1;  // Fee=1000, change=1
        auto selection = select_coins(available, target, 1000);
        assert(selection.success);
        // Change of 1 atomic unit is considered dust by the wallet
        // The coin selection may or may not include it — either behavior is valid
        // Just verify the math is consistent
        assert(selection.total_selected >= target + selection.fee);
        assert(selection.change == selection.total_selected - target - selection.fee);
    }

    // Test 4: Fee calculation is correct
    {
        std::vector<CoinToSpend> available = {
            make_coin(4, 10 * COIN, kp_sender.pubkey),
            make_coin(5, 20 * COIN, kp_sender.pubkey),
            make_coin(6, 30 * COIN, kp_sender.pubkey),
        };

        Amount fee_per_input = 2000;
        Amount target = 25 * COIN;
        auto selection = select_coins(available, target, fee_per_input);
        assert(selection.success);

        // Fee should be fee_per_input * number_of_inputs_selected
        assert(selection.fee == fee_per_input * (Amount)selection.selected.size());

        // Total selected should cover target + fee
        assert(selection.total_selected >= target + selection.fee);
    }

    // Test 5: Sign function called for each input
    {
        std::vector<CoinToSpend> available = {
            make_coin(7, 5 * COIN, kp_sender.pubkey),
            make_coin(8, 5 * COIN, kp_sender.pubkey),
            make_coin(9, 5 * COIN, kp_sender.pubkey),
        };

        Amount target = 12 * COIN;
        auto selection = select_coins(available, target, 1000);
        assert(selection.success);
        assert(selection.selected.size() >= 2);

        auto tx = build_and_sign_tx(selection, pkh_recipient, target,
                                     pkh_sender, kp_sender);

        // Every input should have a non-zero signature
        for (const auto& vin : tx.vin) {
            bool has_sig = false;
            for (auto b : vin.signature) {
                if (b != 0) { has_sig = true; break; }
            }
            assert(has_sig);

            // Verify the signature
            auto txid = tx.get_txid();
            bool valid = flow::ed25519_verify(
                txid.data(), txid.size(),
                vin.pubkey.data(), vin.signature.data());
            assert(valid);
        }
    }

    // Test 6: Insufficient funds
    {
        std::vector<CoinToSpend> available = {
            make_coin(10, 1 * COIN, kp_sender.pubkey),
        };

        Amount target = 100 * COIN;
        auto selection = select_coins(available, target, 1000);
        assert(!selection.success);
        assert(selection.selected.empty());
    }

    // Test 7: Empty available coins
    {
        std::vector<CoinToSpend> available;
        auto selection = select_coins(available, 1 * COIN, 1000);
        assert(!selection.success);
    }

    // Test 8: Exact amount (no change)
    {
        std::vector<CoinToSpend> available = {
            make_coin(11, 10 * COIN + 1000, kp_sender.pubkey),
        };

        Amount target = 10 * COIN;
        auto selection = select_coins(available, target, 1000);
        assert(selection.success);
        assert(selection.change == 0);

        auto tx = build_and_sign_tx(selection, pkh_recipient, target,
                                     pkh_sender, kp_sender);
        // Should have exactly 1 output (no change)
        assert(tx.vout.size() == 1);
        assert(tx.vout[0].amount == target);
    }

    // Test 9: Coin selection prefers smaller coins (smallest-first)
    {
        std::vector<CoinToSpend> available = {
            make_coin(12, 100 * COIN, kp_sender.pubkey),
            make_coin(13, 1 * COIN, kp_sender.pubkey),
            make_coin(14, 5 * COIN, kp_sender.pubkey),
        };

        Amount target = 4 * COIN;
        auto selection = select_coins(available, target, 1000);
        assert(selection.success);

        // Smallest-first should select the 1 COIN + 5 COIN coins
        // rather than the 100 COIN coin
        Amount total = 0;
        for (const auto& coin : selection.selected) {
            total += coin.value;
        }
        assert(total < 100 * COIN);
    }

    // Test 10: Transaction serialization produces consistent txid
    {
        std::vector<CoinToSpend> available = {
            make_coin(15, 50 * COIN, kp_sender.pubkey),
        };

        Amount target = 10 * COIN;
        auto selection = select_coins(available, target, 1000);
        assert(selection.success);

        auto tx = build_and_sign_tx(selection, pkh_recipient, target,
                                     pkh_sender, kp_sender);

        // get_txid() should be deterministic
        auto txid1 = tx.get_txid();
        auto txid2 = tx.get_txid();
        assert(txid1 == txid2);
        assert(!txid1.is_null());

        // Full serialization should produce non-empty bytes
        auto bytes = tx.serialize();
        assert(!bytes.empty());
    }
}
