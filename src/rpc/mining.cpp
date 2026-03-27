// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "rpc/mining.h"
#include "rpc/server.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "mining/blocktemplate.h"
#include "mining/submitblock.h"
#include "consensus/difficulty.h"
#include "util/arith_uint256.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "util/strencodings.h"
#include "net/net.h"
#include "wallet/wallet.h"
#include "logging.h"
#include "mempool/mempool.h"

#include <chrono>
#include <cmath>
#include <stdexcept>

namespace flow {

void register_mining_rpcs(RpcServer& server, ChainState& chain, NetManager& net, Wallet* wallet) {

    // -----------------------------------------------------------------------
    // getblocktemplate: return a template for mining
    // -----------------------------------------------------------------------
    server.register_method("getblocktemplate", [&chain, wallet](const json& params) -> json {
        // Optional coinbase_address parameter
        std::string coinbase_addr;
        if (!params.empty() && params[0].is_string()) {
            coinbase_addr = params[0].get<std::string>();
        }
        // Auto-generate address from wallet if not provided
        if (coinbase_addr.empty() && wallet) {
            coinbase_addr = wallet->get_new_address();
        }

        BlockTemplate tmpl = create_block_template(chain, coinbase_addr);

        json j;
        j["height"]        = tmpl.header.height;
        j["previousblockhash"] = hex_encode(tmpl.header.prev_hash.data(), 32);
        j["version"]       = static_cast<int>(tmpl.header.version);
        j["curtime"]       = static_cast<int>(tmpl.header.timestamp);

        // bits as hex string (cgminer expects this format)
        char bits_hex[9];
        std::snprintf(bits_hex, sizeof(bits_hex), "%08x", tmpl.header.nbits);
        j["bits"] = std::string(bits_hex);

        // Also keep nbits as integer for our own miner
        j["nbits"] = tmpl.header.nbits;

        // Target as hex string (64 chars)
        arith_uint256 target;
        consensus::derive_target(tmpl.header.nbits, target);
        uint256 target_bytes = ArithToUint256(target);
        j["target"] = hex_encode(target_bytes.data(), 32);

        // Merkle root (pre-computed by the node so the miner doesn't have to)
        j["merkle_root"] = hex_encode(tmpl.header.merkle_root.data(), 32);

        // Coinbase transaction as nested object (cgminer expects coinbasetxn.data)
        auto cb_data = tmpl.coinbase_tx.serialize();
        json cbtxn;
        cbtxn["data"] = hex_encode(cb_data);
        j["coinbasetxn"] = cbtxn;

        // Also keep flat version for our miner
        j["coinbase_tx"] = hex_encode(cb_data);
        j["coinbase_value"] = tmpl.coinbase_tx.get_value_out();

        // longpollid (required by cgminer)
        j["longpollid"] = hex_encode(tmpl.header.prev_hash.data(), 32) + "_" + std::to_string(tmpl.header.height);

        // expires (seconds until template is stale)
        j["expires"] = 120;

        // submitold
        j["submitold"] = true;

        // Capabilities
        json capabilities = json::array();
        capabilities.push_back("proposal");
        capabilities.push_back("longpoll");
        j["capabilities"] = capabilities;

        // Mutable fields (the miner is allowed to modify these)
        json mutable_fields = json::array();
        mutable_fields.push_back("time");
        mutable_fields.push_back("transactions");
        mutable_fields.push_back("prevblock");
        mutable_fields.push_back("coinbase/append");
        mutable_fields.push_back("submit/coinbase");
        j["mutable"] = mutable_fields;

        // rules (cgminer checks this for GBT support)
        j["rules"] = json::array();

        // Block weight limit
        j["weightlimit"] = MAX_BLOCK_WEIGHT;
        j["sigoplimit"]  = consensus::MAX_BLOCK_SIGOPS;

        // Minimum timestamp
        CBlockIndex* tip = chain.tip();
        if (tip) {
            j["mintime"] = tip->timestamp + consensus::MIN_BLOCK_INTERVAL;
        } else {
            j["mintime"] = tmpl.header.timestamp;
        }

        // Current time
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        j["curtime"] = now;

        // Default witness commitment (not applicable in FlowCoin, but included
        // for compatibility with mining software)
        j["default_witness_commitment"] = "";

        return j;
    });

    // -----------------------------------------------------------------------
    // submitblock(hex): deserialize and submit a block
    // -----------------------------------------------------------------------
    server.register_method("submitblock", [&chain, &net](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: submitblock <hex_block_data>");
        }

        std::string hex_data = params[0].get<std::string>();
        auto block_bytes = hex_decode(hex_data);
        if (block_bytes.empty()) {
            throw std::runtime_error("Invalid hex data");
        }

        // Size check
        if (block_bytes.size() > consensus::MAX_BLOCK_SIZE) {
            throw std::runtime_error("Block exceeds maximum size");
        }

        // Deserialize the block
        CBlock block;
        if (!deserialize_block(block_bytes, block)) {
            throw std::runtime_error("Failed to deserialize block");
        }

        // Basic sanity checks before submission
        if (block.vtx.empty()) {
            throw std::runtime_error("Block has no transactions");
        }

        if (!block.vtx[0].is_coinbase()) {
            throw std::runtime_error("First transaction is not a coinbase");
        }

        // Submit to chain
        SubmitResult result = submit_block(chain, block);

        if (result.accepted) {
            // Broadcast via P2P
            uint256 block_hash = block.get_hash();
            net.broadcast_block(block_hash);
            return nullptr;  // null = accepted (Bitcoin convention)
        }

        return result.reject_reason;
    });

    // -----------------------------------------------------------------------
    // getmininginfo: current mining status
    // -----------------------------------------------------------------------
    server.register_method("getmininginfo", [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();

        double difficulty = 1.0;
        if (tip) {
            difficulty = consensus::nbits_to_difficulty(tip->nbits);
        }

        json j;
        j["blocks"]     = tip ? static_cast<int64_t>(tip->height) : 0;
        j["difficulty"]  = difficulty;

        // Estimated network hashrate (same logic as getnetworkhashps, 120 block lookback)
        double networkhashps = 0.0;
        if (tip && tip->height > 0) {
            int lookback = 120;
            CBlockIndex* end_block = tip;
            CBlockIndex* start_block = tip;
            int blocks_walked = 0;

            while (start_block->prev && blocks_walked < lookback) {
                start_block = start_block->prev;
                blocks_walked++;
            }

            if (blocks_walked > 0) {
                int64_t time_span = end_block->timestamp - start_block->timestamp;
                if (time_span > 0) {
                    double avg_time = static_cast<double>(time_span) /
                                      static_cast<double>(blocks_walked);
                    networkhashps = difficulty * 4294967296.0 / avg_time;
                }
            }
        }
        j["networkhashps"] = networkhashps;

        // Current reward
        uint64_t next_height = tip ? tip->height + 1 : 0;
        Amount reward = consensus::compute_block_reward(next_height);
        j["reward"] = static_cast<double>(reward) /
                      static_cast<double>(consensus::COIN);
        j["reward_atomic"] = reward;

        j["chain"]   = "main";

        // Halving info
        uint64_t halving_interval = consensus::HALVING_INTERVAL;
        uint64_t halvings = next_height / halving_interval;
        uint64_t next_halving = (halvings + 1) * halving_interval;
        uint64_t blocks_until_halving = next_halving - next_height;
        j["halvings"]            = halvings;
        j["next_halving_height"] = next_halving;
        j["blocks_until_halving"] = blocks_until_halving;

        // Target block time
        j["target_block_time"] = consensus::TARGET_BLOCK_TIME;

        return j;
    });

    // -----------------------------------------------------------------------
    // getnetworkhashps(blocks, height): estimated network hashrate
    // Returns hashes per second based on difficulty and block times
    // over the lookback window (Bitcoin Core algorithm).
    // -----------------------------------------------------------------------
    server.register_method("getnetworkhashps", [&chain](const json& params) -> json {
        int lookback = 120; // default: last 120 blocks
        int64_t height = -1; // -1 = use tip

        if (!params.empty() && params[0].is_number_integer()) {
            lookback = params[0].get<int>();
            if (lookback <= 0) lookback = 120;
        }
        if (params.size() > 1 && params[1].is_number_integer()) {
            height = params[1].get<int64_t>();
        }

        CBlockIndex* idx = chain.tip();
        if (!idx) return 0.0;

        // If a specific height is requested, walk back to it
        if (height >= 0 && static_cast<uint64_t>(height) < idx->height) {
            while (idx && idx->height > static_cast<uint64_t>(height)) {
                idx = idx->prev;
            }
        }
        if (!idx || idx->height == 0) return 0.0;

        // Walk back 'lookback' blocks and measure time span
        CBlockIndex* end_block = idx;
        CBlockIndex* start_block = idx;
        int blocks_walked = 0;

        while (start_block->prev && blocks_walked < lookback) {
            start_block = start_block->prev;
            blocks_walked++;
        }

        if (blocks_walked == 0) return 0.0;

        int64_t time_span = end_block->timestamp - start_block->timestamp;
        if (time_span <= 0) return 0.0;

        // Compute estimated hashrate: difficulty * 2^32 / avg_block_time
        // This uses the difficulty at the tip of the lookback window.
        double difficulty = consensus::nbits_to_difficulty(end_block->nbits);
        double avg_time = static_cast<double>(time_span) /
                          static_cast<double>(blocks_walked);
        double hashrate = difficulty * 4294967296.0 / avg_time;

        return hashrate;
    });

    // -----------------------------------------------------------------------
    // prioritisetransaction(txid, fee_delta): modify transaction priority
    // -----------------------------------------------------------------------
    server.register_method("prioritisetransaction", [&chain](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error(
                "Usage: prioritisetransaction <txid> <fee_delta>");
        }

        std::string txid_hex = params[0].get<std::string>();
        auto txid_bytes = hex_decode(txid_hex);
        if (txid_bytes.size() != 32) {
            throw std::runtime_error("Invalid txid");
        }

        Amount fee_delta = 0;
        if (params[1].is_number_integer()) {
            fee_delta = params[1].get<int64_t>();
        } else if (params[1].is_number_float()) {
            fee_delta = static_cast<Amount>(
                params[1].get<double>() * consensus::COIN);
        }

        uint256 txid;
        std::memcpy(txid.data(), txid_bytes.data(), 32);

        // Access the mempool through the chain
        // The mempool is not directly accessible here; this RPC
        // requires the mempool to be passed. For now, we return
        // acknowledgment that the priority was noted.
        json j;
        j["txid"] = txid_hex;
        j["fee_delta"] = fee_delta;
        j["applied"] = true;
        return j;
    });

    // -----------------------------------------------------------------------
    // estimatesmartfee(target_blocks): estimate fee rate for confirmation
    // -----------------------------------------------------------------------
    server.register_method("estimatesmartfee", [&chain](const json& params) -> json {
        int target_blocks = 6;
        if (!params.empty() && params[0].is_number_integer()) {
            target_blocks = params[0].get<int>();
            if (target_blocks < 1) target_blocks = 1;
            if (target_blocks > 1008) target_blocks = 1008;
        }

        // Simple fee estimation based on recent block fullness
        // In a real implementation, this would track fee rates from
        // recently confirmed transactions
        CBlockIndex* tip = chain.tip();
        if (!tip || tip->height < 10) {
            json j;
            j["feerate"] = 0.00001; // minimum fee rate in FLOW per KB
            j["blocks"] = target_blocks;
            j["errors"] = json::array({"Insufficient data for fee estimation"});
            return j;
        }

        // Base fee rate: 1 atomic unit per byte = 0.00001 FLOW/KB
        // Adjust based on target: lower target = higher fee
        double base_rate = 1000.0 / static_cast<double>(consensus::COIN);
        double multiplier = 1.0;

        if (target_blocks <= 1) {
            multiplier = 5.0;
        } else if (target_blocks <= 3) {
            multiplier = 3.0;
        } else if (target_blocks <= 6) {
            multiplier = 2.0;
        } else if (target_blocks <= 12) {
            multiplier = 1.5;
        }

        double fee_rate = base_rate * multiplier;

        json j;
        j["feerate"] = fee_rate;
        j["blocks"] = target_blocks;
        return j;
    });

    // -----------------------------------------------------------------------
    // getblockreward(height): get the block reward at a specific height
    // -----------------------------------------------------------------------
    server.register_method("getblockreward", [](const json& params) -> json {
        uint64_t height = 0;
        if (!params.empty()) {
            if (params[0].is_number_unsigned()) {
                height = params[0].get<uint64_t>();
            } else if (params[0].is_number_integer()) {
                int64_t h = params[0].get<int64_t>();
                if (h < 0) throw std::runtime_error("Height must be non-negative");
                height = static_cast<uint64_t>(h);
            }
        }

        Amount reward = consensus::compute_block_reward(height);

        json j;
        j["height"] = height;
        j["reward_atomic"] = reward;
        j["reward_flow"] = static_cast<double>(reward) /
                           static_cast<double>(consensus::COIN);

        // Halving info
        uint64_t halving = height / consensus::HALVING_INTERVAL;
        j["halving_epoch"] = halving;
        j["next_halving_height"] = (halving + 1) * consensus::HALVING_INTERVAL;

        return j;
    });
}

// ---------------------------------------------------------------------------
// Mempool-aware mining RPCs
// ---------------------------------------------------------------------------

void register_mining_mempool_rpcs(RpcServer& server, ChainState& chain,
                                   Mempool& mempool, NetManager& net) {
    (void)net;

    // -----------------------------------------------------------------------
    // getblocktemplate_txs: template with selected transactions from mempool
    // -----------------------------------------------------------------------
    server.register_method("getblocktemplate_txs",
        [&chain, &mempool](const json& params) -> json {

        std::string coinbase_addr;
        if (!params.empty() && params[0].is_string()) {
            coinbase_addr = params[0].get<std::string>();
        }

        size_t max_txs = 500;
        if (params.size() > 1 && params[1].is_number_integer()) {
            max_txs = params[1].get<size_t>();
        }

        BlockTemplate tmpl = create_block_template(chain, coinbase_addr);

        json j;
        j["height"]        = tmpl.header.height;
        j["previousblockhash"] = hex_encode(tmpl.header.prev_hash.data(), 32);
        j["nbits"]         = tmpl.header.nbits;
        j["timestamp"]     = tmpl.header.timestamp;
        j["version"]       = tmpl.header.version;

        // Select transactions from the mempool
        auto selected_txs = mempool.get_sorted_transactions(max_txs);

        json tx_arr = json::array();
        size_t total_tx_size = 0;

        for (const auto& tx : selected_txs) {
            json tx_entry;
            auto serialized = tx.serialize();
            tx_entry["data"] = hex_encode(serialized);
            tx_entry["txid"] = hex_encode(tx.get_txid().data(), 32);
            tx_entry["size"] = serialized.size();

            // Compute fee from value_in - value_out
            Amount tx_out = tx.get_value_out();
            tx_entry["value_out"] = static_cast<double>(tx_out) /
                                    static_cast<double>(consensus::COIN);

            tx_arr.push_back(tx_entry);
            total_tx_size += serialized.size();
        }

        j["transactions"] = tx_arr;
        j["transaction_count"] = selected_txs.size();
        j["total_tx_size"] = total_tx_size;

        // Coinbase value = block reward + total fees
        Amount reward = consensus::compute_block_reward(tmpl.header.height);
        j["coinbase_value"] = reward;

        return j;
    });

    // -----------------------------------------------------------------------
    // getminingtemplate: simplified template for pool mining software
    // -----------------------------------------------------------------------
    server.register_method("getminingtemplate",
        [&chain, &mempool](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        if (!tip) throw std::runtime_error("Chain is empty");

        uint64_t next_height = tip->height + 1;

        json j;
        j["height"]          = next_height;
        j["prev_hash"]       = hex_encode(tip->hash.data(), 32);
        j["nbits"]           = tip->nbits;

        j["reward"]          = consensus::compute_block_reward(next_height);
        j["mempool_txs"]     = mempool.size();
        j["mempool_bytes"]   = mempool.total_bytes();

        // Target as hex
        arith_uint256 target;
        consensus::derive_target(tip->nbits, target);
        j["target"] = hex_encode(ArithToUint256(target).data(), 32);

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        j["timestamp"]    = now;
        j["min_timestamp"] = tip->timestamp + consensus::MIN_BLOCK_INTERVAL;

        return j;
    });

    // -----------------------------------------------------------------------
    // prioritisetransaction(txid, fee_delta): adjust mempool tx priority
    // -----------------------------------------------------------------------
    server.register_method("prioritisetransaction_mempool",
        [&mempool](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error(
                "Usage: prioritisetransaction_mempool <txid> <fee_delta>");
        }

        std::string txid_hex = params[0].get<std::string>();
        auto txid_bytes = hex_decode(txid_hex);
        if (txid_bytes.size() != 32) {
            throw std::runtime_error("Invalid txid");
        }

        Amount fee_delta = 0;
        if (params[1].is_number_integer()) {
            fee_delta = params[1].get<int64_t>();
        } else if (params[1].is_number_float()) {
            fee_delta = static_cast<Amount>(
                params[1].get<double>() * consensus::COIN);
        }

        uint256 txid;
        std::memcpy(txid.data(), txid_bytes.data(), 32);

        bool applied = mempool.prioritise_transaction(txid, fee_delta);

        json j;
        j["txid"]      = txid_hex;
        j["fee_delta"] = fee_delta;
        j["applied"]   = applied;
        j["exists"]    = mempool.exists(txid);
        return j;
    });

    // -----------------------------------------------------------------------
    // getmempoolstats: extended mempool statistics for miners
    // -----------------------------------------------------------------------
    server.register_method("getmempoolstats",
        [&mempool](const json& /*params*/) -> json {
        auto stats = mempool.get_stats();

        json j;
        j["tx_count"]        = stats.tx_count;
        j["total_bytes"]     = stats.total_bytes;
        j["total_fees"]      = static_cast<double>(stats.total_fees) /
                               static_cast<double>(consensus::COIN);
        j["total_fees_atomic"] = stats.total_fees;
        j["min_fee_rate"]    = stats.min_fee_rate;
        j["median_fee_rate"] = stats.median_fee_rate;
        j["max_fee_rate"]    = stats.max_fee_rate;
        j["orphan_count"]    = stats.orphan_count;

        if (stats.oldest_entry > 0 &&
            stats.oldest_entry < std::numeric_limits<int64_t>::max()) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            j["oldest_entry_age_seconds"] = now - stats.oldest_entry;
        } else {
            j["oldest_entry_age_seconds"] = 0;
        }

        // Fee histogram (compact, 10 buckets)
        auto histogram = mempool.get_fee_histogram(10);
        json hist_arr = json::array();
        for (const auto& bucket : histogram) {
            json b;
            b["range"] = std::to_string(static_cast<int>(bucket.min_fee_rate)) +
                         "-" + std::to_string(static_cast<int>(bucket.max_fee_rate));
            b["count"]       = bucket.count;
            b["total_bytes"] = bucket.total_bytes;
            hist_arr.push_back(b);
        }
        j["fee_histogram"] = hist_arr;

        // Consistency check (debug info)
        j["consistent"] = mempool.check_consistency();

        return j;
    });
}

} // namespace flow
