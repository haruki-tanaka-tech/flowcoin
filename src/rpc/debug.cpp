// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "rpc/debug.h"
#include "rpc/server.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "chain/blockstore.h"
#include "chain/utxo.h"
#include "consensus/difficulty.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "consensus/validation.h"
#include "crypto/keys.h"
#include "crypto/bech32.h"
#include "hash/keccak.h"
#include "mempool/mempool.h"
#include "util/arith_uint256.h"
#include "util/strencodings.h"
#include "wallet/wallet.h"

#include <chrono>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <sstream>

namespace flow {

void register_debug_rpcs(RpcServer& server, ChainState& chain,
                         Mempool& mempool, Wallet& wallet) {

    // -----------------------------------------------------------------------
    // getblocktemplate_debug: detailed template for debugging miners
    // -----------------------------------------------------------------------
    server.register_method("getblocktemplate_debug",
        [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        if (!tip) throw std::runtime_error("Chain is empty");

        uint64_t next_height = tip->height + 1;
        auto dims = consensus::compute_growth(next_height);
        Amount reward = consensus::compute_block_reward(next_height);

        json j;
        j["next_height"] = next_height;
        j["prev_hash"] = hex_encode(tip->hash.data(), 32);
        j["prev_val_loss"] = tip->val_loss;
        j["reward_atomic"] = reward;
        j["reward_flow"] = static_cast<double>(reward) /
                           static_cast<double>(consensus::COIN);

        // Model dimensions
        json m;
        m["d_model"] = dims.d_model;
        m["n_layers"] = dims.n_layers;
        m["n_heads"] = dims.n_heads;
        m["d_head"] = dims.d_head;
        m["d_ff"] = dims.d_ff;
        m["n_slots"] = dims.n_slots;
        m["top_k"] = dims.top_k;
        m["gru_dim"] = dims.gru_dim;
        m["conv_kernel"] = dims.conv_kernel;
        m["vocab"] = dims.vocab;
        m["seq_len"] = dims.seq_len;
        j["model"] = m;

        // Difficulty info
        j["nbits"] = tip->nbits;
        arith_uint256 target;
        consensus::derive_target(tip->nbits, target);
        j["target_hex"] = hex_encode(ArithToUint256(target).data(), 32);

        // Estimate parameter count
        uint64_t params = dims.vocab * dims.d_model; // embedding
        params += dims.n_layers * (4 * dims.d_model * dims.d_model +
                                    2 * dims.d_model * dims.d_ff +
                                    3 * dims.d_model * dims.d_model +
                                    4 * dims.d_model +
                                    dims.d_model * dims.conv_kernel);
        params += 2 * dims.n_slots * dims.d_model; // slot memory
        params += dims.d_model * dims.vocab; // output head
        j["estimated_params"] = params;
        j["estimated_params_mb"] = static_cast<double>(params * 4) / (1024.0 * 1024.0);

        // Timing
        j["target_block_time"] = consensus::TARGET_BLOCK_TIME;
        j["min_block_interval"] = consensus::MIN_BLOCK_INTERVAL;
        j["tip_timestamp"] = tip->timestamp;
        j["min_next_timestamp"] = tip->timestamp + consensus::MIN_BLOCK_INTERVAL;

        // Growth phase
        bool dims_growing = (next_height < consensus::DIM_FREEZE_HEIGHT);
        j["growth_phase"] = dims_growing ? "dimension_growth" : "slot_growth";
        j["dims_frozen"]  = !dims_growing;

        // Halving info
        int era = static_cast<int>(next_height / consensus::HALVING_INTERVAL);
        j["halving_era"] = era;
        j["blocks_until_halving"] =
            (era + 1) * consensus::HALVING_INTERVAL - next_height;

        // Retarget info
        int retarget_pos = static_cast<int>(next_height % consensus::RETARGET_INTERVAL);
        j["retarget_position"] = retarget_pos;
        j["blocks_until_retarget"] = consensus::RETARGET_INTERVAL - retarget_pos;

        return j;
    });

    // -----------------------------------------------------------------------
    // estimatesmartfee(conf_target): estimate fee for confirmation target
    // -----------------------------------------------------------------------
    server.register_method("estimatesmartfee",
        [&mempool](const json& params) -> json {
        int conf_target = 6;
        if (!params.empty() && params[0].is_number()) {
            conf_target = params[0].get<int>();
        }
        if (conf_target < 1) conf_target = 1;
        if (conf_target > 1000) conf_target = 1000;

        // Simple fee estimation based on mempool state.
        // In production, this would use historical block data and a
        // more sophisticated fee estimator. For now, use a simple model.
        size_t mempool_size = mempool.size();

        // Base fee: 1000 atomic units per input
        double base_fee = 1000.0;

        // If mempool is congested, increase fee
        if (mempool_size > 100) {
            base_fee *= 1.0 + (mempool_size - 100) * 0.01;
        }

        // Lower fee for higher confirmation targets (willing to wait)
        double discount = 1.0 / std::sqrt(static_cast<double>(conf_target));
        double estimated_fee = base_fee * discount;

        json j;
        j["feerate"] = estimated_fee / static_cast<double>(consensus::COIN);
        j["feerate_atomic"] = static_cast<int64_t>(estimated_fee);
        j["blocks"] = conf_target;
        j["mempool_size"] = mempool_size;
        return j;
    });

    // -----------------------------------------------------------------------
    // getblockchaininfo_debug: extended chain info with internal state
    // -----------------------------------------------------------------------
    server.register_method("getblockchaininfo_debug",
        [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();

        json j;
        j["chain"] = "main";
        j["blocks"] = tip ? static_cast<int64_t>(tip->height) : 0;
        j["bestblockhash"] = tip ? hex_encode(tip->hash.data(), 32) : std::string(64, '0');
        j["difficulty_nbits"] = tip ? tip->nbits : consensus::INITIAL_NBITS;

        // Block tree statistics
        j["block_tree_size"] = chain.block_tree().size();

        if (tip) {
            j["tip_val_loss"] = tip->val_loss;
            j["tip_d_model"] = tip->d_model;
            j["tip_n_layers"] = tip->n_layers;
            j["tip_n_slots"] = tip->n_slots;
            // tip_train_steps removed (not a consensus field)
            j["tip_stagnation"] = tip->stagnation_count;
            j["tip_improving_blocks"] = tip->improving_blocks;

            // Walk back to compute statistics
            int total_improving = 0;
            float total_loss = 0;
            float min_loss = tip->val_loss;
            float max_loss = tip->val_loss;
            int count = 0;
            CBlockIndex* idx = tip;

            while (idx && count < 100) {
                if (idx->is_improving()) total_improving++;
                total_loss += idx->val_loss;
                if (idx->val_loss < min_loss) min_loss = idx->val_loss;
                if (idx->val_loss > max_loss) max_loss = idx->val_loss;
                count++;
                idx = idx->prev;
            }

            j["last_100_improving"] = total_improving;
            j["last_100_avg_loss"] = (count > 0) ? total_loss / count : 0.0f;
            j["last_100_min_loss"] = min_loss;
            j["last_100_max_loss"] = max_loss;

            // Time between last 10 blocks
            idx = tip;
            std::vector<int64_t> timestamps;
            for (int i = 0; i < 11 && idx; ++i) {
                timestamps.push_back(idx->timestamp);
                idx = idx->prev;
            }

            if (timestamps.size() >= 2) {
                std::vector<int64_t> intervals;
                for (size_t i = 0; i + 1 < timestamps.size(); ++i) {
                    intervals.push_back(timestamps[i] - timestamps[i + 1]);
                }

                int64_t total_interval = 0;
                int64_t min_interval = intervals[0];
                int64_t max_interval = intervals[0];
                for (auto iv : intervals) {
                    total_interval += iv;
                    if (iv < min_interval) min_interval = iv;
                    if (iv > max_interval) max_interval = iv;
                }
                j["avg_block_time"] = static_cast<double>(total_interval) / intervals.size();
                j["min_block_time"] = min_interval;
                j["max_block_time"] = max_interval;
            }
        }

        // Consensus parameters
        json params;
        params["coin"] = consensus::COIN;
        params["max_supply"] = consensus::MAX_SUPPLY;
        params["halving_interval"] = consensus::HALVING_INTERVAL;
        params["target_block_time"] = consensus::TARGET_BLOCK_TIME;
        params["retarget_interval"] = consensus::RETARGET_INTERVAL;
        params["coinbase_maturity"] = consensus::COINBASE_MATURITY;
        params["max_block_size"] = consensus::MAX_BLOCK_SIZE;
        params["max_delta_size"] = consensus::MAX_DELTA_SIZE;
        params["eval_tokens"] = consensus::EVAL_TOKENS;
        params["eval_seq_len"] = consensus::EVAL_SEQ_LEN;
        j["consensus_params"] = params;

        // Assume-valid info
        j["assume_valid_enabled"] = !chain.assume_valid_hash().is_null();
        if (!chain.assume_valid_hash().is_null()) {
            j["assume_valid_hash"] = hex_encode(chain.assume_valid_hash().data(), 32);
        }

        // TX index
        j["txindex_enabled"] = (chain.tx_index() != nullptr);

        return j;
    });

    // -----------------------------------------------------------------------
    // getsupplyinfo(height): compute supply statistics at a given height
    // -----------------------------------------------------------------------
    server.register_method("getsupplyinfo", [](const json& params) -> json {
        uint64_t height = 0;
        if (!params.empty() && params[0].is_number()) {
            height = params[0].get<uint64_t>();
        }

        // Compute total supply minted up to this height
        Amount total_minted = 0;
        Amount current_reward = consensus::INITIAL_REWARD;
        int current_era = 0;
        uint64_t blocks_in_era = 0;

        for (uint64_t h = 0; h <= height; ++h) {
            int era = static_cast<int>(h / consensus::HALVING_INTERVAL);
            if (era != current_era) {
                // Sum the reward for the completed era
                total_minted += current_reward * blocks_in_era;
                current_reward = consensus::compute_block_reward(h);
                current_era = era;
                blocks_in_era = 0;
            }
            blocks_in_era++;
        }
        total_minted += current_reward * blocks_in_era;

        // Percentage of max supply
        double pct = (consensus::MAX_SUPPLY > 0)
            ? static_cast<double>(total_minted) / static_cast<double>(consensus::MAX_SUPPLY) * 100.0
            : 0.0;

        json j;
        j["height"] = height;
        j["total_minted_atomic"] = total_minted;
        j["total_minted_flow"] = static_cast<double>(total_minted) /
                                 static_cast<double>(consensus::COIN);
        j["max_supply_flow"] = 21000000.0;
        j["percentage_minted"] = pct;
        j["current_reward_atomic"] = consensus::compute_block_reward(height);
        j["current_reward_flow"] = static_cast<double>(consensus::compute_block_reward(height)) /
                                    static_cast<double>(consensus::COIN);
        j["current_era"] = static_cast<int>(height / consensus::HALVING_INTERVAL);
        j["blocks_until_halving"] =
            consensus::HALVING_INTERVAL - (height % consensus::HALVING_INTERVAL);

        return j;
    });

    // -----------------------------------------------------------------------
    // generatetoaddress(nblocks, address): simulation helper (regtest)
    // Returns an empty array (actual block generation requires mining engine).
    // -----------------------------------------------------------------------
    server.register_method("generatetoaddress", [](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("Usage: generatetoaddress <nblocks> <address>");
        }
        int nblocks = params[0].get<int>();
        std::string addr = params[1].get<std::string>();

        if (nblocks <= 0 || nblocks > 100) {
            throw std::runtime_error("nblocks must be between 1 and 100");
        }

        // Validate address
        auto decoded = bech32m_decode(addr);
        if (!decoded.valid) {
            throw std::runtime_error("Invalid address");
        }

        // In regtest mode, this would trigger immediate block generation.
        // For mainnet/testnet, return informational response.
        json result = json::array();
        // No blocks actually generated on mainnet
        json j;
        j["blocks"] = result;
        j["note"] = "Block generation requires the mining engine. "
                     "Use flowminer.py for actual block production.";
        j["requested"] = nblocks;
        j["address"] = addr;
        return j;
    });

    // -----------------------------------------------------------------------
    // getblockstats_range(start, end): compute stats over a range of blocks
    // -----------------------------------------------------------------------
    server.register_method("getblockstats_range",
        [&chain](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("Usage: getblockstats_range <start> <end>");
        }

        uint64_t start = params[0].get<uint64_t>();
        uint64_t end_h = params[1].get<uint64_t>();

        if (end_h < start) {
            throw std::runtime_error("End must be >= start");
        }
        if (end_h - start > 100) {
            throw std::runtime_error("Range too large (max 100 blocks)");
        }

        CBlockIndex* tip = chain.tip();
        if (!tip || end_h > tip->height) {
            throw std::runtime_error("End height exceeds chain tip");
        }

        // Collect block indices
        std::vector<CBlockIndex*> indices;
        CBlockIndex* idx = tip;
        while (idx) {
            if (idx->height >= start && idx->height <= end_h) {
                indices.push_back(idx);
            }
            if (idx->height == 0 || idx->height < start) break;
            idx = idx->prev;
        }

        std::reverse(indices.begin(), indices.end());

        float total_loss = 0;
        int total_tx = 0;
        int improving = 0;

        for (CBlockIndex* bi : indices) {
            total_loss += bi->val_loss;
            total_tx += bi->n_tx;
            if (bi->is_improving()) improving++;
        }

        int count = static_cast<int>(indices.size());

        json j;
        j["start"] = start;
        j["end"] = end_h;
        j["block_count"] = count;
        j["avg_val_loss"] = (count > 0) ? total_loss / count : 0.0f;
        j["total_transactions"] = total_tx;
        j["improving_blocks"] = improving;
        j["improving_pct"] = (count > 0) ? 100.0 * improving / count : 0.0;

        if (indices.size() >= 2) {
            int64_t time_span = indices.back()->timestamp - indices.front()->timestamp;
            j["time_span_seconds"] = time_span;
            j["avg_block_time"] = (count > 1) ? static_cast<double>(time_span) / (count - 1) : 0.0;
        }

        return j;
    });

    // -----------------------------------------------------------------------
    // getheaders_compact(start, count): return compact header summaries
    // -----------------------------------------------------------------------
    server.register_method("getheaders_compact",
        [&chain](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("Usage: getheaders_compact <start_height> <count>");
        }

        uint64_t start = params[0].get<uint64_t>();
        int count = params[1].get<int>();
        if (count <= 0 || count > 2016) {
            throw std::runtime_error("Count must be between 1 and 2016");
        }

        CBlockIndex* tip = chain.tip();
        if (!tip) throw std::runtime_error("Chain is empty");

        std::vector<CBlockIndex*> indices;
        CBlockIndex* idx = tip;
        while (idx) {
            if (idx->height >= start &&
                idx->height < start + static_cast<uint64_t>(count)) {
                indices.push_back(idx);
            }
            if (idx->height == 0 || idx->height < start) break;
            idx = idx->prev;
        }

        std::reverse(indices.begin(), indices.end());

        json result = json::array();
        for (CBlockIndex* bi : indices) {
            json h;
            h["h"] = bi->height;
            h["t"] = bi->timestamp;
            h["vl"] = bi->val_loss;
            h["nb"] = bi->nbits;
            // train_steps removed from consensus
            h["dm"] = bi->d_model;
            h["nl"] = bi->n_layers;
            // First 8 hex chars of hash as a short identifier
            h["id"] = hex_encode(bi->hash.data(), 4);
            result.push_back(h);
        }

        return result;
    });
}

} // namespace flow
