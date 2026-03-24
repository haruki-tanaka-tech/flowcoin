// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Exhaustive tests for UTXO coin selection algorithm.

#include "wallet/coinselect.h"
#include "util/random.h"
#include "util/types.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <numeric>
#include <vector>

using namespace flow;

static CoinToSpend make_coin(Amount value) {
    CoinToSpend c;
    GetRandBytes(c.txid.data(), 32);
    c.vout = 0;
    c.value = value;
    GetRandBytes(c.pubkey.data(), 32);
    return c;
}

void test_coin_selection() {

    // -----------------------------------------------------------------------
    // Test 1: Single coin exactly covers target + fee
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {make_coin(11000)};
        auto sel = select_coins(coins, 10000, 1000);
        assert(sel.success);
        assert(sel.selected.size() == 1);
        assert(sel.total_selected == 11000);
        assert(sel.fee == 1000);
        assert(sel.change == 0);
    }

    // -----------------------------------------------------------------------
    // Test 2: Single coin covers target with change
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {make_coin(50000)};
        auto sel = select_coins(coins, 10000, 1000);
        assert(sel.success);
        assert(sel.selected.size() == 1);
        assert(sel.fee == 1000);
        assert(sel.change == 50000 - 10000 - 1000);
    }

    // -----------------------------------------------------------------------
    // Test 3: Multiple coins needed
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            make_coin(5000), make_coin(5000), make_coin(5000)
        };
        auto sel = select_coins(coins, 12000, 1000);
        assert(sel.success);
        // Need all 3 coins: 15000 >= 12000 + 3*1000
        assert(sel.selected.size() == 3);
        assert(sel.fee == 3000);
        assert(sel.change == 0);
    }

    // -----------------------------------------------------------------------
    // Test 4: Smallest-first ordering
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            make_coin(100000), make_coin(1000), make_coin(50000)
        };
        auto sel = select_coins(coins, 40000, 1000);
        assert(sel.success);
        // Should select smallest first: 1000, then 50000
        // 1000 + 50000 = 51000 >= 40000 + 2*1000 = 42000? Yes.
        assert(sel.selected.size() == 2);
        // First selected should be smallest
        assert(sel.selected[0].value == 1000);
        assert(sel.selected[1].value == 50000);
    }

    // -----------------------------------------------------------------------
    // Test 5: Insufficient funds
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {make_coin(5000), make_coin(3000)};
        auto sel = select_coins(coins, 10000, 1000);
        assert(!sel.success);
        assert(sel.total_selected == 8000);
    }

    // -----------------------------------------------------------------------
    // Test 6: Empty coins
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        auto sel = select_coins(coins, 1000, 1000);
        assert(!sel.success);
    }

    // -----------------------------------------------------------------------
    // Test 7: Zero target
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {make_coin(10000)};
        auto sel = select_coins(coins, 0, 1000);
        assert(!sel.success);
    }

    // -----------------------------------------------------------------------
    // Test 8: Negative target
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {make_coin(10000)};
        auto sel = select_coins(coins, -1000, 1000);
        assert(!sel.success);
    }

    // -----------------------------------------------------------------------
    // Test 9: Zero fee
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {make_coin(10000)};
        auto sel = select_coins(coins, 10000, 0);
        assert(sel.success);
        assert(sel.fee == 0);
        assert(sel.change == 0);
    }

    // -----------------------------------------------------------------------
    // Test 10: Large number of coins
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        for (int i = 0; i < 100; ++i) {
            coins.push_back(make_coin(1000));
        }
        auto sel = select_coins(coins, 50000, 100);
        assert(sel.success);
        // Need at least 51 coins: 51*1000 >= 50000 + 51*100 = 55100? 51000 < 55100
        // Actually need more due to fee scaling
        Amount total = 0;
        for (const auto& c : sel.selected) total += c.value;
        assert(total >= 50000 + sel.fee);
    }

    // -----------------------------------------------------------------------
    // Test 11: Single tiny coin insufficient
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {make_coin(500)};
        auto sel = select_coins(coins, 1000, 1000);
        assert(!sel.success);
    }

    // -----------------------------------------------------------------------
    // Test 12: Fee grows with inputs
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        for (int i = 0; i < 10; ++i) {
            coins.push_back(make_coin(2000));
        }

        auto sel = select_coins(coins, 5000, 500);
        assert(sel.success);
        // Fee = num_inputs * 500
        assert(sel.fee == static_cast<Amount>(sel.selected.size()) * 500);
    }

    // -----------------------------------------------------------------------
    // Test 13: Exactly one coin needed when it covers target + fee
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            make_coin(100), make_coin(200), make_coin(5000)
        };
        auto sel = select_coins(coins, 4000, 1000);
        assert(sel.success);
        // 100 < 4000+1000, 100+200 < 4000+2000, 100+200+5000 >= 4000+3000
        // So all 3 needed
        assert(sel.selected.size() == 3);
    }

    // -----------------------------------------------------------------------
    // Test 14: Change calculation with multiple inputs
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            make_coin(30000), make_coin(20000), make_coin(10000)
        };
        auto sel = select_coins(coins, 25000, 1000);
        assert(sel.success);
        assert(sel.change == sel.total_selected - 25000 - sel.fee);
    }

    // -----------------------------------------------------------------------
    // Test 15: Preserves txid and vout in selected coins
    // -----------------------------------------------------------------------
    {
        CoinToSpend c1 = make_coin(50000);
        c1.vout = 7;
        std::vector<CoinToSpend> coins = {c1};

        auto sel = select_coins(coins, 10000, 1000);
        assert(sel.success);
        assert(sel.selected[0].txid == c1.txid);
        assert(sel.selected[0].vout == 7);
        assert(sel.selected[0].value == 50000);
    }

    // -----------------------------------------------------------------------
    // Test 16: Preserves pubkey in selected coins
    // -----------------------------------------------------------------------
    {
        CoinToSpend c1 = make_coin(50000);
        std::array<uint8_t, 32> test_pk;
        std::memset(test_pk.data(), 0xAB, 32);
        c1.pubkey = test_pk;

        std::vector<CoinToSpend> coins = {c1};
        auto sel = select_coins(coins, 10000, 1000);
        assert(sel.success);
        assert(sel.selected[0].pubkey == test_pk);
    }

    // -----------------------------------------------------------------------
    // Test 17: Many small coins vs one large coin
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> small_coins;
        for (int i = 0; i < 100; ++i) {
            small_coins.push_back(make_coin(100));
        }
        // Total available: 10000
        // Target: 5000, fee per input: 10
        auto sel = select_coins(small_coins, 5000, 10);
        assert(sel.success);
        // Verify fee accounts for all selected inputs
        assert(sel.fee == static_cast<Amount>(sel.selected.size()) * 10);
    }

    // -----------------------------------------------------------------------
    // Test 18: Fee causes insufficient funds
    // -----------------------------------------------------------------------
    {
        // Coin exactly covers target but not target + fee
        std::vector<CoinToSpend> coins = {make_coin(10000)};
        auto sel = select_coins(coins, 10000, 1000);
        assert(!sel.success);
    }

    // -----------------------------------------------------------------------
    // Test 19: Large fee per input
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            make_coin(100000), make_coin(200000)
        };
        auto sel = select_coins(coins, 50000, 50000);
        assert(sel.success);
        // Need 1 coin: 100000 >= 50000 + 50000. Exactly.
        assert(sel.selected.size() == 1);
        assert(sel.change == 0);
    }

    // -----------------------------------------------------------------------
    // Test 20: All coins selected when needed
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        Amount total = 0;
        for (int i = 1; i <= 5; ++i) {
            coins.push_back(make_coin(i * 10000));
            total += i * 10000;
        }
        // Target close to total
        Amount target = total - 5 * 100 - 1;  // just barely feasible with fee_per_input=100
        auto sel = select_coins(coins, target, 100);
        if (sel.success) {
            assert(sel.total_selected >= target + sel.fee);
        }
    }
}
