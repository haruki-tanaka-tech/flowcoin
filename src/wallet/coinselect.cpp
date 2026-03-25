// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "wallet/coinselect.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <random>
#include <set>

namespace flow {

// ---------------------------------------------------------------------------
// Backward-compatible interface
// ---------------------------------------------------------------------------

CoinSelection select_coins(const std::vector<CoinToSpend>& available,
                            Amount target, Amount fee_per_input) {
    return coinselect::auto_select(available, target, fee_per_input);
}

namespace coinselect {

// ---------------------------------------------------------------------------
// Fee estimation helpers
// ---------------------------------------------------------------------------

size_t estimate_tx_size(int num_inputs, int num_outputs) {
    // Header: version(4) + locktime(8) = 12
    // Varint for vin_count and vout_count: 1 each (assuming < 253)
    // Per input: txid(32) + index(4) + pubkey(32) + signature(64) = 132
    // Per output: amount(8) + pubkey_hash(32) = 40
    return 14 + static_cast<size_t>(num_inputs) * 132 +
           static_cast<size_t>(num_outputs) * 40;
}

Amount estimate_fee(int num_inputs, int num_outputs, Amount fee_per_input) {
    (void)num_outputs;
    return fee_per_input * static_cast<Amount>(num_inputs);
}

Amount estimate_fee_by_size(int num_inputs, int num_outputs,
                             Amount fee_rate_per_byte) {
    size_t size = estimate_tx_size(num_inputs, num_outputs);
    return fee_rate_per_byte * static_cast<Amount>(size);
}

// ---------------------------------------------------------------------------
// UTXO filtering
// ---------------------------------------------------------------------------

std::vector<CoinToSpend> filter_spendable(
        const std::vector<CoinToSpend>& coins,
        uint64_t tip_height,
        int coinbase_maturity) {
    std::vector<CoinToSpend> result;
    result.reserve(coins.size());

    for (const auto& coin : coins) {
        // Skip zero-value coins
        if (coin.value <= 0) continue;

        // Check coinbase maturity
        if (coin.is_coinbase) {
            if (tip_height < coin.height + static_cast<uint64_t>(coinbase_maturity)) {
                continue;
            }
        }

        result.push_back(coin);
    }

    return result;
}

std::vector<CoinToSpend> sort_by_effective_value(
        const std::vector<CoinToSpend>& coins,
        Amount fee_per_input) {
    std::vector<CoinToSpend> result;
    result.reserve(coins.size());

    for (const auto& coin : coins) {
        // Only include coins whose value exceeds the cost to spend them
        if (coin.value > fee_per_input) {
            result.push_back(coin);
        }
    }

    // Sort by effective value descending
    std::sort(result.begin(), result.end(),
              [fee_per_input](const CoinToSpend& a, const CoinToSpend& b) {
                  return (a.value - fee_per_input) > (b.value - fee_per_input);
              });

    return result;
}

Amount total_value(const std::vector<CoinToSpend>& coins) {
    Amount total = 0;
    for (const auto& coin : coins) {
        total += coin.value;
    }
    return total;
}

std::vector<std::vector<CoinToSpend>> group_by_address(
        const std::vector<CoinToSpend>& coins) {
    // Group by pubkey
    std::map<std::array<uint8_t, 32>, std::vector<CoinToSpend>> groups;
    for (const auto& coin : coins) {
        groups[coin.pubkey].push_back(coin);
    }

    std::vector<std::vector<CoinToSpend>> result;
    result.reserve(groups.size());
    for (auto& [pubkey, group] : groups) {
        result.push_back(std::move(group));
    }

    return result;
}

// ---------------------------------------------------------------------------
// Algorithm 1: Smallest-first
// ---------------------------------------------------------------------------

CoinSelection smallest_first(const std::vector<CoinToSpend>& available,
                              Amount target, Amount fee_per_input) {
    CoinSelection result;
    result.total_selected = 0;
    result.fee = 0;
    result.change = 0;
    result.success = false;
    result.algorithm_used = "smallest_first";

    if (target <= 0) {
        result.error = "target must be positive";
        return result;
    }

    // Sort by value ascending (smallest first)
    std::vector<CoinToSpend> sorted = available;
    std::sort(sorted.begin(), sorted.end(),
              [](const CoinToSpend& a, const CoinToSpend& b) {
                  return a.value < b.value;
              });

    // Accumulate coins until we cover target + fee
    Amount accumulated = 0;
    std::vector<CoinToSpend> selected;

    for (const auto& coin : sorted) {
        selected.push_back(coin);
        accumulated += coin.value;

        Amount fee = fee_per_input * static_cast<Amount>(selected.size());
        Amount needed = target + fee;

        if (accumulated >= needed) {
            result.selected = std::move(selected);
            result.total_selected = accumulated;
            result.fee = fee;
            result.change = accumulated - target - fee;
            result.success = true;
            return result;
        }
    }

    // Could not cover the target + fee
    result.selected = std::move(selected);
    result.total_selected = accumulated;
    result.fee = fee_per_input * static_cast<Amount>(result.selected.size());
    result.change = 0;
    result.success = false;
    result.error = "insufficient-funds";
    return result;
}

// ---------------------------------------------------------------------------
// Algorithm 2: Largest-first
// ---------------------------------------------------------------------------

CoinSelection largest_first(const std::vector<CoinToSpend>& available,
                             Amount target, Amount fee_per_input) {
    CoinSelection result;
    result.total_selected = 0;
    result.fee = 0;
    result.change = 0;
    result.success = false;
    result.algorithm_used = "largest_first";

    if (target <= 0) {
        result.error = "target must be positive";
        return result;
    }

    // Sort by value descending (largest first)
    std::vector<CoinToSpend> sorted = available;
    std::sort(sorted.begin(), sorted.end(),
              [](const CoinToSpend& a, const CoinToSpend& b) {
                  return a.value > b.value;
              });

    // Accumulate until target is met
    Amount accumulated = 0;
    std::vector<CoinToSpend> selected;

    for (const auto& coin : sorted) {
        selected.push_back(coin);
        accumulated += coin.value;

        Amount fee = fee_per_input * static_cast<Amount>(selected.size());
        Amount needed = target + fee;

        if (accumulated >= needed) {
            result.selected = std::move(selected);
            result.total_selected = accumulated;
            result.fee = fee;
            result.change = accumulated - target - fee;
            result.success = true;
            return result;
        }
    }

    result.selected = std::move(selected);
    result.total_selected = accumulated;
    result.fee = fee_per_input * static_cast<Amount>(result.selected.size());
    result.change = 0;
    result.success = false;
    result.error = "insufficient-funds";
    return result;
}

// ---------------------------------------------------------------------------
// Algorithm 3: Knapsack (random walk approximation)
// ---------------------------------------------------------------------------

CoinSelection knapsack(const std::vector<CoinToSpend>& available,
                        Amount target, Amount fee_per_input) {
    CoinSelection result;
    result.total_selected = 0;
    result.fee = 0;
    result.change = 0;
    result.success = false;
    result.algorithm_used = "knapsack";

    if (target <= 0) {
        result.error = "target must be positive";
        return result;
    }

    if (available.empty()) {
        result.error = "no coins available";
        return result;
    }

    // First check: can we cover the target with all coins?
    Amount all_total = 0;
    for (const auto& coin : available) {
        all_total += coin.value;
    }
    Amount max_fee = fee_per_input * static_cast<Amount>(available.size());
    if (all_total < target + max_fee) {
        result.error = "insufficient-funds";
        return result;
    }

    // Step 1: Check if any single coin exactly matches target + fee
    Amount fee_for_one = fee_per_input;
    Amount exact_target = target + fee_for_one;

    const CoinToSpend* exact_match = nullptr;
    Amount smallest_excess = std::numeric_limits<Amount>::max();
    const CoinToSpend* best_excess = nullptr;

    for (const auto& coin : available) {
        if (coin.value == exact_target) {
            exact_match = &coin;
            break;
        }
        if (coin.value > exact_target) {
            Amount excess = coin.value - exact_target;
            if (excess < smallest_excess) {
                smallest_excess = excess;
                best_excess = &coin;
            }
        }
    }

    if (exact_match) {
        result.selected.push_back(*exact_match);
        result.total_selected = exact_match->value;
        result.fee = fee_for_one;
        result.change = 0;
        result.success = true;
        return result;
    }

    // Step 2: Random walk approach
    // Sort coins by value descending
    std::vector<CoinToSpend> sorted = available;
    std::sort(sorted.begin(), sorted.end(),
              [](const CoinToSpend& a, const CoinToSpend& b) {
                  return a.value > b.value;
              });

    // Use a deterministic random generator seeded by the target value
    // for reproducibility
    std::mt19937 rng(static_cast<uint32_t>(target & 0xFFFFFFFF));

    // Run multiple random walk iterations and keep the best result
    CoinSelection best_result;
    best_result.success = false;
    Amount best_change = std::numeric_limits<Amount>::max();

    constexpr int NUM_ITERATIONS = 1000;

    for (int iter = 0; iter < NUM_ITERATIONS; ++iter) {
        std::vector<CoinToSpend> selected;
        Amount accumulated = 0;
        bool found = false;

        // Random walk: for each coin, flip a coin to decide inclusion
        for (const auto& coin : sorted) {
            bool include;
            if (iter == 0) {
                // First iteration: deterministic greedy
                Amount current_fee = fee_per_input *
                    static_cast<Amount>(selected.size() + 1);
                include = (accumulated < target + current_fee);
            } else {
                // Subsequent iterations: random inclusion with bias
                // towards including when we're below target
                Amount current_fee = fee_per_input *
                    static_cast<Amount>(selected.size() + 1);
                if (accumulated >= target + current_fee) {
                    // Already have enough, include with 30% probability
                    include = (rng() % 100 < 30);
                } else {
                    // Need more, include with 70% probability
                    include = (rng() % 100 < 70);
                }
            }

            if (include) {
                selected.push_back(coin);
                accumulated += coin.value;

                Amount fee = fee_per_input * static_cast<Amount>(selected.size());
                if (accumulated >= target + fee) {
                    found = true;
                    Amount change = accumulated - target - fee;

                    if (change < best_change) {
                        best_change = change;
                        best_result.selected = selected;
                        best_result.total_selected = accumulated;
                        best_result.fee = fee;
                        best_result.change = change;
                        best_result.success = true;
                        best_result.algorithm_used = "knapsack";
                    }

                    // If we found an exact match (no change), stop searching
                    if (change == 0) {
                        return best_result;
                    }
                    break;
                }
            }
        }
    }

    if (best_result.success) {
        return best_result;
    }

    // Fallback: use the coin with smallest excess if we found one
    if (best_excess) {
        result.selected.push_back(*best_excess);
        result.total_selected = best_excess->value;
        result.fee = fee_for_one;
        result.change = best_excess->value - target - fee_for_one;
        result.success = true;
        return result;
    }

    // Final fallback: smallest-first greedy
    return smallest_first(available, target, fee_per_input);
}

// ---------------------------------------------------------------------------
// Algorithm 4: Branch and Bound
// ---------------------------------------------------------------------------

namespace {

struct BnBState {
    const std::vector<CoinToSpend>* coins;
    Amount target;
    Amount fee_per_input;
    Amount cost_of_change;
    int max_depth;
    bool found;
    std::vector<bool> best_selection;
    Amount best_value;

    void search(int depth, Amount current_value, int num_selected,
                std::vector<bool>& selection) {
        if (found) return;

        Amount fee = fee_per_input * static_cast<Amount>(num_selected);
        Amount needed = target + fee;

        // If we've accumulated enough
        if (current_value >= needed) {
            Amount excess = current_value - needed;
            // Accept if the excess is less than the cost of change
            // (it's cheaper to "donate" the excess to the miner)
            if (excess <= cost_of_change) {
                found = true;
                best_selection = selection;
                best_value = current_value;
                return;
            }
            // Excess too high, prune this branch
            return;
        }

        // If we've considered all coins, stop
        if (depth >= static_cast<int>(coins->size())) return;

        // Pruning: check if including all remaining coins could reach target
        Amount remaining = 0;
        for (int i = depth; i < static_cast<int>(coins->size()); ++i) {
            remaining += (*coins)[i].value;
        }
        Amount max_fee = fee_per_input *
            static_cast<Amount>(num_selected +
                static_cast<int>(coins->size()) - depth);
        if (current_value + remaining < target + max_fee) {
            return; // Cannot reach target with remaining coins
        }

        // Depth limit to prevent exponential blowup
        if (depth >= max_depth) return;

        // Branch: include this coin
        selection[depth] = true;
        search(depth + 1, current_value + (*coins)[depth].value,
               num_selected + 1, selection);

        if (found) return;

        // Branch: exclude this coin
        selection[depth] = false;
        search(depth + 1, current_value, num_selected, selection);
    }
};

} // anonymous namespace

CoinSelection branch_and_bound(const std::vector<CoinToSpend>& available,
                                Amount target, Amount fee_per_input,
                                Amount cost_of_change) {
    CoinSelection result;
    result.total_selected = 0;
    result.fee = 0;
    result.change = 0;
    result.success = false;
    result.algorithm_used = "branch_and_bound";

    if (target <= 0) {
        result.error = "target must be positive";
        return result;
    }

    if (available.empty()) {
        result.error = "no coins available";
        return result;
    }

    // Sort coins by value descending for better pruning
    std::vector<CoinToSpend> sorted = available;
    std::sort(sorted.begin(), sorted.end(),
              [](const CoinToSpend& a, const CoinToSpend& b) {
                  return a.value > b.value;
              });

    // Limit the number of coins to search through to prevent
    // exponential blowup
    constexpr int MAX_BNB_COINS = 200;
    constexpr int MAX_BNB_DEPTH = 30;

    if (static_cast<int>(sorted.size()) > MAX_BNB_COINS) {
        sorted.resize(MAX_BNB_COINS);
    }

    BnBState state;
    state.coins = &sorted;
    state.target = target;
    state.fee_per_input = fee_per_input;
    state.cost_of_change = cost_of_change;
    state.max_depth = std::min(static_cast<int>(sorted.size()), MAX_BNB_DEPTH);
    state.found = false;
    state.best_value = 0;

    std::vector<bool> selection(sorted.size(), false);
    state.search(0, 0, 0, selection);

    if (!state.found) {
        result.error = "no exact match found";
        return result;
    }

    // Build the result from the best selection
    for (size_t i = 0; i < sorted.size(); ++i) {
        if (state.best_selection[i]) {
            result.selected.push_back(sorted[i]);
        }
    }

    result.total_selected = state.best_value;
    result.fee = fee_per_input * static_cast<Amount>(result.selected.size());
    result.change = result.total_selected - target - result.fee;
    result.success = true;

    return result;
}

// ---------------------------------------------------------------------------
// Auto-select
// ---------------------------------------------------------------------------

CoinSelection auto_select(const std::vector<CoinToSpend>& available,
                           Amount target, Amount fee_per_input) {
    if (target <= 0 || available.empty()) {
        CoinSelection fail;
        fail.success = false;
        fail.total_selected = 0;
        fail.fee = 0;
        fail.change = 0;
        fail.error = (target <= 0) ? "target must be positive" : "no coins available";
        fail.algorithm_used = "auto_select";
        return fail;
    }

    // Step 1: Try branch-and-bound for an exact match (no change output)
    // This saves the cost of creating and later spending a change output.
    CoinSelection bnb_result = branch_and_bound(available, target, fee_per_input);
    if (bnb_result.success && bnb_result.change == 0) {
        bnb_result.algorithm_used = "auto_select/branch_and_bound";
        return bnb_result;
    }

    // Step 2: Try knapsack for a close match with minimal change
    CoinSelection knapsack_result = knapsack(available, target, fee_per_input);
    if (knapsack_result.success) {
        knapsack_result.algorithm_used = "auto_select/knapsack";
        return knapsack_result;
    }

    // Step 3: Fall back to smallest-first (always succeeds if funds available)
    CoinSelection sf_result = smallest_first(available, target, fee_per_input);
    if (sf_result.success) {
        sf_result.algorithm_used = "auto_select/smallest_first";
    }
    return sf_result;
}

} // namespace coinselect (close before waste analysis functions)

// ---------------------------------------------------------------------------
// Waste analysis (in flow namespace, not coinselect)
// ---------------------------------------------------------------------------

WasteAnalysis calculate_waste(const CoinSelection& selection,
                               Amount target,
                               Amount fee_per_input,
                               Amount cost_of_change) {
    WasteAnalysis analysis;
    analysis.num_inputs = static_cast<int>(selection.selected.size());
    analysis.input_fees = fee_per_input * static_cast<Amount>(analysis.num_inputs);
    analysis.has_change = (selection.change > 0);

    if (analysis.has_change) {
        // Waste includes the cost of creating and spending the change output
        analysis.change_cost = cost_of_change;
        analysis.excess = 0;
    } else {
        // No change: the excess goes to the miner as additional fee
        analysis.change_cost = 0;
        analysis.excess = selection.total_selected - target - analysis.input_fees;
        if (analysis.excess < 0) analysis.excess = 0;
    }

    analysis.waste = analysis.input_fees + analysis.change_cost + analysis.excess;
    return analysis;
}

CoinSelection select_min_waste(const std::vector<CoinToSpend>& available,
                                Amount target, Amount fee_per_input) {
    using namespace coinselect;
    // Run all algorithms and pick the one with minimum waste
    struct Candidate {
        CoinSelection selection;
        Amount waste;
    };

    std::vector<Candidate> candidates;

    // Try BnB
    auto bnb = branch_and_bound(available, target, fee_per_input);
    if (bnb.success) {
        auto w = calculate_waste(bnb, target, fee_per_input);
        candidates.push_back({std::move(bnb), w.waste});
    }

    // Try knapsack
    auto kn = knapsack(available, target, fee_per_input);
    if (kn.success) {
        auto w = calculate_waste(kn, target, fee_per_input);
        candidates.push_back({std::move(kn), w.waste});
    }

    // Try smallest-first
    auto sf = smallest_first(available, target, fee_per_input);
    if (sf.success) {
        auto w = calculate_waste(sf, target, fee_per_input);
        candidates.push_back({std::move(sf), w.waste});
    }

    // Try largest-first
    auto lf = largest_first(available, target, fee_per_input);
    if (lf.success) {
        auto w = calculate_waste(lf, target, fee_per_input);
        candidates.push_back({std::move(lf), w.waste});
    }

    if (candidates.empty()) {
        CoinSelection fail;
        fail.success = false;
        fail.error = "insufficient-funds";
        fail.algorithm_used = "select_min_waste";
        return fail;
    }

    // Find minimum waste
    size_t best_idx = 0;
    for (size_t i = 1; i < candidates.size(); ++i) {
        if (candidates[i].waste < candidates[best_idx].waste) {
            best_idx = i;
        }
    }

    auto& best = candidates[best_idx].selection;
    best.algorithm_used = "min_waste/" + best.algorithm_used;
    return best;
}

} // namespace flow
