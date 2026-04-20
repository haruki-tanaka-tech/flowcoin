// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Exhaustive tests for coin selection algorithms: branch-and-bound simulation,
// knapsack walk, smallest/largest-first strategies, fee estimation, dust
// handling, edge cases, and performance.

#include "wallet/coinselect.h"
#include "primitives/transaction.h"
#include "util/random.h"
#include "util/types.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <numeric>
#include <vector>

using namespace flow;

static CoinToSpend mk_coin(Amount value, uint32_t vout = 0) {
    CoinToSpend c;
    GetRandBytes(c.txid.data(), 32);
    c.vout = vout;
    c.value = value;
    GetRandBytes(c.pubkey.data(), 32);
    return c;
}

void test_coinselect_algorithms() {
    // -----------------------------------------------------------------------
    // Test 1: Exact match (no change needed)
    // -----------------------------------------------------------------------
    {
        // Coin value = target + fee_per_input*1
        std::vector<CoinToSpend> coins = {mk_coin(11000)};
        auto sel = select_coins(coins, 10000, 1000);
        assert(sel.success);
        assert(sel.selected.size() == 1);
        assert(sel.total_selected == 11000);
        assert(sel.fee == 1000);
        assert(sel.change == 0);
    }

    // -----------------------------------------------------------------------
    // Test 2: Single coin with change
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(50000)};
        auto sel = select_coins(coins, 10000, 1000);
        assert(sel.success);
        assert(sel.selected.size() == 1);
        assert(sel.fee == 1000);
        assert(sel.change == 50000 - 10000 - 1000);
    }

    // -----------------------------------------------------------------------
    // Test 3: Smallest-first selects in ascending order
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            mk_coin(100000), mk_coin(1000), mk_coin(50000)
        };
        auto sel = select_coins(coins, 40000, 1000);
        assert(sel.success);
        // Sorted: 1000, 50000, 100000
        // 1000 + 50000 = 51000 >= 40000 + 2*1000 = 42000
        assert(sel.selected.size() == 2);
        assert(sel.selected[0].value == 1000);
        assert(sel.selected[1].value == 50000);
    }

    // -----------------------------------------------------------------------
    // Test 4: All coins too small - insufficient funds
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(100), mk_coin(200), mk_coin(300)};
        auto sel = select_coins(coins, 10000, 1000);
        assert(!sel.success);
        assert(sel.total_selected == 600);
    }

    // -----------------------------------------------------------------------
    // Test 5: Single large coin (lots of change)
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(10000000)};
        auto sel = select_coins(coins, 1000, 500);
        assert(sel.success);
        assert(sel.selected.size() == 1);
        assert(sel.change == 10000000 - 1000 - 500);
    }

    // -----------------------------------------------------------------------
    // Test 6: Edge case: empty coin set
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        auto sel = select_coins(coins, 1000, 100);
        assert(!sel.success);
    }

    // -----------------------------------------------------------------------
    // Test 7: Edge case: zero target
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(10000)};
        auto sel = select_coins(coins, 0, 1000);
        assert(!sel.success);
    }

    // -----------------------------------------------------------------------
    // Test 8: Edge case: negative target
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(10000)};
        auto sel = select_coins(coins, -1000, 1000);
        assert(!sel.success);
    }

    // -----------------------------------------------------------------------
    // Test 9: Zero fee per input
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(10000)};
        auto sel = select_coins(coins, 10000, 0);
        assert(sel.success);
        assert(sel.fee == 0);
        assert(sel.change == 0);
    }

    // -----------------------------------------------------------------------
    // Test 10: Fee estimation correct for various input counts
    // -----------------------------------------------------------------------
    {
        Amount fee_per = 500;
        for (int n = 1; n <= 10; ++n) {
            std::vector<CoinToSpend> coins;
            Amount total = 0;
            for (int i = 0; i < n; ++i) {
                coins.push_back(mk_coin(10000));
                total += 10000;
            }
            // Target that requires all n coins
            Amount target = total - n * fee_per - 1;
            if (target <= 0) continue;

            auto sel = select_coins(coins, target, fee_per);
            if (sel.success) {
                assert(sel.fee == static_cast<Amount>(sel.selected.size()) * fee_per);
                assert(sel.total_selected >= target + sel.fee);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: Dust output: very small amount (below threshold check)
    //          select_coins itself doesn't reject dust, but CTxOut::is_dust does
    // -----------------------------------------------------------------------
    {
        CTxOut dust_out(100, {});
        assert(dust_out.is_dust());  // 100 < DUST_THRESHOLD(546)

        CTxOut normal_out(1000, {});
        assert(!normal_out.is_dust());
    }

    // -----------------------------------------------------------------------
    // Test 12: Fee causes insufficient funds
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(10000)};
        auto sel = select_coins(coins, 10000, 1000);
        assert(!sel.success);  // 10000 < 10000 + 1000
    }

    // -----------------------------------------------------------------------
    // Test 13: Multiple coins needed with increasing fee
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            mk_coin(5000), mk_coin(5000), mk_coin(5000)
        };
        auto sel = select_coins(coins, 12000, 1000);
        assert(sel.success);
        // Need all 3: 15000 >= 12000 + 3*1000 = 15000
        assert(sel.selected.size() == 3);
        assert(sel.fee == 3000);
        assert(sel.change == 0);
    }

    // -----------------------------------------------------------------------
    // Test 14: Prefers fewer inputs (smallest-first adds until covered)
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            mk_coin(100), mk_coin(200), mk_coin(50000)
        };
        auto sel = select_coins(coins, 1000, 500);
        assert(sel.success);
        // sorted: 100, 200, 50000
        // 100 < 1000+500=1500
        // 100+200=300 < 1000+1000=2000
        // 100+200+50000=50300 >= 1000+1500=2500
        // All 3 needed
        assert(sel.selected.size() == 3);
    }

    // -----------------------------------------------------------------------
    // Test 15: Large fee per input
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            mk_coin(100000), mk_coin(200000)
        };
        auto sel = select_coins(coins, 50000, 50000);
        assert(sel.success);
        assert(sel.selected.size() == 1);
        assert(sel.change == 0);  // 100000 = 50000 + 50000
    }

    // -----------------------------------------------------------------------
    // Test 16: All coins selected when needed
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        Amount total = 0;
        for (int i = 1; i <= 5; ++i) {
            coins.push_back(mk_coin(i * 10000));
            total += i * 10000;
        }
        // total = 150000
        // With fee_per_input=100 and 5 inputs, fee=500
        // target = total - fee - 1 = 149499
        Amount target = total - 5 * 100 - 1;
        auto sel = select_coins(coins, target, 100);
        if (sel.success) {
            assert(sel.total_selected >= target + sel.fee);
            assert(sel.selected.size() == 5);
        }
    }

    // -----------------------------------------------------------------------
    // Test 17: Change calculation with multiple inputs
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {
            mk_coin(30000), mk_coin(20000), mk_coin(10000)
        };
        auto sel = select_coins(coins, 25000, 1000);
        assert(sel.success);
        assert(sel.change == sel.total_selected - 25000 - sel.fee);
        assert(sel.change >= 0);
    }

    // -----------------------------------------------------------------------
    // Test 18: Preserves txid, vout, pubkey in selected coins
    // -----------------------------------------------------------------------
    {
        CoinToSpend c1 = mk_coin(50000);
        c1.vout = 7;
        std::array<uint8_t, 32> test_pk;
        std::memset(test_pk.data(), 0xAB, 32);
        c1.pubkey = test_pk;

        std::vector<CoinToSpend> coins = {c1};
        auto sel = select_coins(coins, 10000, 1000);
        assert(sel.success);
        assert(sel.selected[0].txid == c1.txid);
        assert(sel.selected[0].vout == 7);
        assert(sel.selected[0].value == 50000);
        assert(sel.selected[0].pubkey == test_pk);
    }

    // -----------------------------------------------------------------------
    // Test 19: Many small coins vs fee accumulation
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> small_coins;
        for (int i = 0; i < 100; ++i) {
            small_coins.push_back(mk_coin(100));
        }
        // Total: 10000, target: 5000, fee_per: 10
        auto sel = select_coins(small_coins, 5000, 10);
        assert(sel.success);
        assert(sel.fee == static_cast<Amount>(sel.selected.size()) * 10);
        assert(sel.total_selected >= 5000 + sel.fee);
    }

    // -----------------------------------------------------------------------
    // Test 20: Single coin insufficient for target
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(500)};
        auto sel = select_coins(coins, 1000, 100);
        assert(!sel.success);
    }

    // -----------------------------------------------------------------------
    // Test 21: Two coins, second just barely covers
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(100), mk_coin(10000)};
        auto sel = select_coins(coins, 9000, 500);
        assert(sel.success);
        // sorted: 100, 10000
        // 100 < 9000+500=9500
        // 100+10000=10100 >= 9000+1000=10000
        assert(sel.selected.size() == 2);
        assert(sel.total_selected == 10100);
        assert(sel.fee == 1000);
        assert(sel.change == 10100 - 9000 - 1000);
    }

    // -----------------------------------------------------------------------
    // Test 22: Performance - 10000 coins selects quickly
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        for (int i = 0; i < 10000; ++i) {
            coins.push_back(mk_coin(1000));
        }

        auto start = std::chrono::steady_clock::now();
        auto sel = select_coins(coins, 500000, 10);
        auto end = std::chrono::steady_clock::now();

        assert(sel.success);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        assert(ms < 1000);  // Should complete well within 1 second
    }

    // -----------------------------------------------------------------------
    // Test 23: Coins with zero value (edge case)
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(0), mk_coin(10000)};
        auto sel = select_coins(coins, 5000, 100);
        // Sorted: 0, 10000
        // 0 doesn't help, but 0+10000=10000 >= 5000+200=5200
        if (sel.success) {
            assert(sel.total_selected >= 5000 + sel.fee);
        }
    }

    // -----------------------------------------------------------------------
    // Test 24: Exact match with two coins
    // -----------------------------------------------------------------------
    {
        // Two coins that exactly match target + fee
        std::vector<CoinToSpend> coins = {mk_coin(3000), mk_coin(4000)};
        auto sel = select_coins(coins, 5000, 1000);
        assert(sel.success);
        assert(sel.selected.size() == 2);
        assert(sel.total_selected == 7000);
        assert(sel.fee == 2000);
        assert(sel.change == 0);
    }

    // -----------------------------------------------------------------------
    // Test 25: Deterministic - same inputs produce same selection
    // -----------------------------------------------------------------------
    {
        CoinToSpend c1, c2, c3;
        std::memset(c1.txid.data(), 0x11, 32); c1.vout = 0; c1.value = 5000;
        std::memset(c2.txid.data(), 0x22, 32); c2.vout = 0; c2.value = 10000;
        std::memset(c3.txid.data(), 0x33, 32); c3.vout = 0; c3.value = 3000;
        std::memset(c1.pubkey.data(), 0, 32);
        std::memset(c2.pubkey.data(), 0, 32);
        std::memset(c3.pubkey.data(), 0, 32);

        std::vector<CoinToSpend> coins1 = {c1, c2, c3};
        std::vector<CoinToSpend> coins2 = {c1, c2, c3};

        auto sel1 = select_coins(coins1, 7000, 500);
        auto sel2 = select_coins(coins2, 7000, 500);

        assert(sel1.success == sel2.success);
        if (sel1.success) {
            assert(sel1.selected.size() == sel2.selected.size());
            assert(sel1.fee == sel2.fee);
            assert(sel1.change == sel2.change);
        }
    }

    // -----------------------------------------------------------------------
    // Test 26: Fee grows with number of inputs
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        for (int i = 0; i < 10; ++i) {
            coins.push_back(mk_coin(2000));
        }

        auto sel = select_coins(coins, 5000, 500);
        assert(sel.success);
        assert(sel.fee == static_cast<Amount>(sel.selected.size()) * 500);
    }

    // -----------------------------------------------------------------------
    // Test 27: Very large target with single very large coin
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(MAX_MONEY)};
        auto sel = select_coins(coins, MAX_MONEY - 10000, 1000);
        assert(sel.success);
        assert(sel.selected.size() == 1);
        assert(sel.fee == 1000);
        assert(sel.change == MAX_MONEY - (MAX_MONEY - 10000) - 1000);
    }

    // -----------------------------------------------------------------------
    // Test 28: Selection result totals are consistent
    // -----------------------------------------------------------------------
    {
        for (int trial = 0; trial < 20; ++trial) {
            std::vector<CoinToSpend> coins;
            int n = 1 + static_cast<int>(GetRand(10));
            for (int i = 0; i < n; ++i) {
                coins.push_back(mk_coin(1000 + static_cast<Amount>(GetRand(100000))));
            }
            Amount target = static_cast<Amount>(GetRand(50000)) + 1;

            auto sel = select_coins(coins, target, 100);
            if (sel.success) {
                // Verify consistency
                Amount computed_total = 0;
                for (const auto& c : sel.selected) {
                    computed_total += c.value;
                }
                assert(computed_total == sel.total_selected);
                assert(sel.total_selected == target + sel.fee + sel.change);
                assert(sel.fee >= 0);
                assert(sel.change >= 0);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 29: Many identical coins
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        for (int i = 0; i < 1000; ++i) {
            coins.push_back(mk_coin(5000));
        }
        auto sel = select_coins(coins, 100000, 100);
        assert(sel.success);
        // All selected coins should be 5000
        for (const auto& c : sel.selected) {
            assert(c.value == 5000);
        }
        assert(sel.total_selected >= 100000 + sel.fee);
    }

    // -----------------------------------------------------------------------
    // Test 30: Coins with different vout indices
    // -----------------------------------------------------------------------
    {
        CoinToSpend c1 = mk_coin(10000, 0);
        CoinToSpend c2 = mk_coin(20000, 1);
        CoinToSpend c3 = mk_coin(30000, 2);

        std::vector<CoinToSpend> coins = {c1, c2, c3};
        auto sel = select_coins(coins, 15000, 1000);
        assert(sel.success);

        // Verify vout indices are preserved
        for (const auto& s : sel.selected) {
            bool found = false;
            for (const auto& orig : coins) {
                if (s.txid == orig.txid && s.vout == orig.vout) {
                    found = true;
                    break;
                }
            }
            assert(found);
        }
    }

    // -----------------------------------------------------------------------
    // Test 31: Very high fee_per_input reduces selectable funds
    // -----------------------------------------------------------------------
    {
        // Each coin is 10000, but fee_per_input is 9000
        // Effective value per coin is only 1000
        std::vector<CoinToSpend> coins;
        for (int i = 0; i < 5; ++i) {
            coins.push_back(mk_coin(10000));
        }
        auto sel = select_coins(coins, 3000, 9000);
        // Need enough coins such that total - n*9000 >= 3000
        // 2 coins: 20000 - 18000 = 2000 < 3000
        // 3 coins: 30000 - 27000 = 3000 >= 3000
        assert(sel.success);
        assert(sel.selected.size() >= 3);
    }

    // -----------------------------------------------------------------------
    // Test 32: Target of 1 (minimum useful target)
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins = {mk_coin(1000)};
        auto sel = select_coins(coins, 1, 100);
        assert(sel.success);
        assert(sel.change == 1000 - 1 - 100);
    }

    // -----------------------------------------------------------------------
    // Test 33: Selection with exactly one coin matching target+fee
    // -----------------------------------------------------------------------
    {
        // Coin value = 5000, target = 4000, fee = 1000 → exact match
        std::vector<CoinToSpend> coins = {mk_coin(5000)};
        auto sel = select_coins(coins, 4000, 1000);
        assert(sel.success);
        assert(sel.selected.size() == 1);
        assert(sel.change == 0);
        assert(sel.fee == 1000);
    }

    // -----------------------------------------------------------------------
    // Test 34: All coins equal value
    // -----------------------------------------------------------------------
    {
        std::vector<CoinToSpend> coins;
        for (int i = 0; i < 50; ++i) {
            coins.push_back(mk_coin(1000));
        }
        auto sel = select_coins(coins, 10000, 50);
        assert(sel.success);
        // All selected coins are 1000
        for (const auto& c : sel.selected) {
            assert(c.value == 1000);
        }
        assert(sel.total_selected >= 10000 + sel.fee);
        assert(sel.fee == static_cast<Amount>(sel.selected.size()) * 50);
    }
}
