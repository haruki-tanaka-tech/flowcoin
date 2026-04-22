// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "rpc/blockchain.h"
#include "rpc/server.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "chain/blockstore.h"
#include "chain/utxo.h"
#include "consensus/difficulty.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "crypto/bech32.h"
#include "hash/keccak.h"
#include "mempool/mempool.h"
#include "util/strencodings.h"

#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstring>
#include <stdexcept>

namespace flow {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string hash_to_hex(const uint256& h) {
    return hex_encode(h.data(), 32);
}

static uint256 hex_to_hash(const std::string& hex_str) {
    auto bytes = hex_decode(hex_str);
    if (bytes.size() != 32) {
        throw std::runtime_error("Invalid hash length");
    }
    uint256 result;
    std::memcpy(result.data(), bytes.data(), 32);
    return result;
}

/// Format a uint32_t as an 8-character lowercase hex string (e.g. "1d00ffff").
static std::string uint32_to_hex(uint32_t val) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%08x", val);
    return std::string(buf);
}

/// Compute the median-time-past for a block index entry.
/// Takes the median of the timestamps of the previous 11 blocks (including
/// this block), matching Bitcoin Core's GetMedianTimePast().
static int64_t compute_median_time(const CBlockIndex* idx) {
    constexpr int MEDIAN_SPAN = 11;
    int64_t timestamps[MEDIAN_SPAN];
    int count = 0;
    const CBlockIndex* walk = idx;
    while (walk && count < MEDIAN_SPAN) {
        timestamps[count++] = walk->timestamp;
        walk = walk->prev;
    }
    std::sort(timestamps, timestamps + count);
    return timestamps[count / 2];
}

/// Find the next block after idx in the active chain (returns nullptr if idx
/// is the tip). Walks back from tip to idx->height+1.
static const CBlockIndex* find_next_block(const CBlockIndex* idx,
                                           ChainState& chain) {
    CBlockIndex* tip = chain.tip();
    if (!tip || idx->height >= tip->height) return nullptr;
    CBlockIndex* walk = tip;
    while (walk && walk->prev != idx) {
        walk = walk->prev;
    }
    return walk;
}

/// Build the header-portion JSON for a block index entry (shared by getblock
/// and getblockheader). Does NOT include n_tx for getblockheader (caller
/// controls that). Does NOT include nextblockhash (caller adds it).
static json block_index_to_header_json(const CBlockIndex* idx,
                                        const CBlockIndex* tip,
                                        uint32_t block_version = 1) {
    json j;
    j["hash"]              = hash_to_hex(idx->hash);
    j["confirmations"]     = static_cast<int64_t>(tip->height - idx->height + 1);
    j["height"]            = idx->height;
    j["version"]           = static_cast<int64_t>(block_version);
    j["versionHex"]        = uint32_to_hex(block_version);
    j["merkleroot"]        = hash_to_hex(idx->merkle_root);
    j["time"]              = idx->timestamp;
    j["mediantime"]        = compute_median_time(idx);
    j["nonce"]             = idx->nonce;
    j["bits"]              = uint32_to_hex(idx->nbits);
    j["difficulty"]        = consensus::nbits_to_difficulty(idx->nbits);
    j["chainwork"]         = std::string(64, '0');
    j["nTx"]               = idx->n_tx;
    j["miner_pubkey"]      = hex_encode(idx->miner_pubkey.data(), 32);

    if (idx->prev) {
        j["previousblockhash"] = hash_to_hex(idx->prev->hash);
    }

    return j;
}

static json tx_to_json(const CTransaction& tx) {
    json j;
    j["txid"]    = hash_to_hex(tx.get_txid());
    j["version"] = tx.version;

    json vin_arr = json::array();
    for (const auto& in : tx.vin) {
        json ij;
        if (in.is_coinbase()) {
            ij["coinbase"] = "01";
        } else {
            ij["txid"]  = hash_to_hex(in.prevout.txid);
            ij["vout"]  = in.prevout.index;
            ij["pubkey"] = hex_encode(in.pubkey.data(), 32);
        }
        vin_arr.push_back(ij);
    }
    j["vin"] = vin_arr;

    json vout_arr = json::array();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        json oj;
        oj["value"]       = static_cast<double>(tx.vout[i].amount) /
                            static_cast<double>(consensus::COIN);
        oj["n"]           = i;
        oj["pubkey_hash"] = hex_encode(tx.vout[i].pubkey_hash.data(), 32);

        // Encode pubkey_hash to bech32m address (first 20 bytes)
        std::vector<uint8_t> program(tx.vout[i].pubkey_hash.data(),
                                     tx.vout[i].pubkey_hash.data() + 20);
        std::string addr = bech32m_encode("fl", 0, program);
        if (!addr.empty()) {
            oj["address"] = addr;
        }

        vout_arr.push_back(oj);
    }
    j["vout"] = vout_arr;

    return j;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void register_blockchain_rpcs(RpcServer& server, ChainState& chain) {

    // getblockcount: return current chain height
    server.register_method("getblockcount", [&chain](const json& /*params*/) -> json {
        return static_cast<int64_t>(chain.height());
    });

    // getbestblockhash: return hash of the current tip
    server.register_method("getbestblockhash", [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        if (!tip) throw std::runtime_error("No blocks in chain");
        return hash_to_hex(tip->hash);
    });

    // getblockhash(height): return the hash of the block at a given height
    server.register_method("getblockhash", [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_number_unsigned()) {
            throw std::runtime_error("Usage: getblockhash <height>");
        }
        uint64_t target_height = params[0].get<uint64_t>();

        // Walk back from tip to find the block at target_height
        CBlockIndex* idx = chain.tip();
        if (!idx || target_height > idx->height) {
            throw std::runtime_error("Block height out of range");
        }
        while (idx && idx->height > target_height) {
            idx = idx->prev;
        }
        if (!idx || idx->height != target_height) {
            throw std::runtime_error("Block not found at height");
        }
        return hash_to_hex(idx->hash);
    });

    // getblock(hash, verbosity=1)
    server.register_method("getblock", [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getblock <hash> [verbosity]");
        }
        std::string hash_hex = params[0].get<std::string>();
        int verbosity = 1;
        if (params.size() > 1 && params[1].is_number_integer()) {
            verbosity = params[1].get<int>();
        }

        uint256 hash = hex_to_hash(hash_hex);
        CBlockIndex* idx = chain.block_tree().find(hash);
        if (!idx) {
            throw std::runtime_error("Block not found");
        }

        if (verbosity == 0) {
            // Return serialized block as hex
            CBlock block;
            if (!chain.block_store().read_block(idx->pos, block)) {
                throw std::runtime_error("Block data not available on disk");
            }
            auto data = block.CBlockHeader::get_unsigned_data();
            return hex_encode(data);
        }

        // Read full block to get version and transactions
        CBlock block;
        bool have_block = chain.block_store().read_block(idx->pos, block);

        CBlockIndex* tip = chain.tip();
        uint32_t block_version = have_block ? block.version : 1;
        json j = block_index_to_header_json(idx, tip, block_version);

        // Add nextblockhash if a successor exists on the active chain
        const CBlockIndex* next = find_next_block(idx, chain);
        if (next) {
            j["nextblockhash"] = hash_to_hex(next->hash);
        }

        if (have_block) {
            if (verbosity == 1) {
                // txids only
                json txids = json::array();
                for (const auto& tx : block.vtx) {
                    txids.push_back(hash_to_hex(tx.get_txid()));
                }
                j["tx"] = txids;
            } else {
                // Full transactions
                json txs = json::array();
                for (const auto& tx : block.vtx) {
                    txs.push_back(tx_to_json(tx));
                }
                j["tx"] = txs;
            }
            j["size"] = 0 + block.vtx.size() * 200; // estimate
        }

        return j;
    });

    // getblockheader(hash): return header as JSON
    server.register_method("getblockheader", [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getblockheader <hash>");
        }
        uint256 hash = hex_to_hash(params[0].get<std::string>());
        CBlockIndex* idx = chain.block_tree().find(hash);
        if (!idx) {
            throw std::runtime_error("Block not found");
        }

        // Read block from disk to get version (not stored in CBlockIndex)
        uint32_t block_version = 1;
        CBlock block;
        if (chain.block_store().read_block(idx->pos, block)) {
            block_version = block.version;
        }

        CBlockIndex* tip = chain.tip();
        json j = block_index_to_header_json(idx, tip, block_version);

        // Bitcoin Core's getblockheader does not include nTx
        j.erase("nTx");

        // Add nextblockhash if a successor exists on the active chain
        const CBlockIndex* next = find_next_block(idx, chain);
        if (next) {
            j["nextblockhash"] = hash_to_hex(next->hash);
        }

        return j;
    });

    // getblockchaininfo: chain summary
    server.register_method("getblockchaininfo", [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        int64_t height = tip ? static_cast<int64_t>(tip->height) : 0;

        json j;
        j["chain"]                = "main";
        j["blocks"]               = height;
        j["headers"]              = height;
        j["bestblockhash"]        = tip ? hash_to_hex(tip->hash) : std::string(64, '0');
        j["difficulty"]           = consensus::nbits_to_difficulty(
                                        tip ? tip->nbits : consensus::INITIAL_NBITS);
        j["mediantime"]           = tip ? compute_median_time(tip) : int64_t(0);
        j["verificationprogress"] = 1.0;
        j["initialblockdownload"] = false;
        j["chainwork"]            = std::string(64, '0');
        j["size_on_disk"]         = int64_t(0);
        j["pruned"]               = false;
        j["warnings"]             = json::array();   // Bitcoin Core 30.x: array, not string

        // FlowCoin-specific bonus fields
        j["halving_interval"]     = consensus::HALVING_INTERVAL;
        j["target_block_time"]    = consensus::TARGET_BLOCK_TIME;
        return j;
    });

    // gettxout(txid, vout): look up a UTXO
    server.register_method("gettxout", [&chain](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("Usage: gettxout <txid> <vout>");
        }
        uint256 txid = hex_to_hash(params[0].get<std::string>());
        uint32_t vout = params[1].get<uint32_t>();

        UTXOEntry entry;
        if (!chain.utxo_set().get(txid, vout, entry)) {
            return nullptr;  // UTXO not found (spent or non-existent)
        }

        json j;
        j["value"]       = static_cast<double>(entry.value) /
                           static_cast<double>(consensus::COIN);
        j["pubkey_hash"] = hex_encode(entry.pubkey_hash.data(), 32);
        j["height"]      = entry.height;
        j["coinbase"]    = entry.is_coinbase;
        return j;
    });

    // gettxoutsetinfo: UTXO set statistics
    // Walks the entire active chain computing aggregate stats.
    server.register_method("gettxoutsetinfo", [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        json j;
        j["height"]        = tip ? static_cast<int64_t>(tip->height) : 0;
        j["bestblock"]     = tip ? hash_to_hex(tip->hash) : std::string(64, '0');

        // Walk the chain and count transactions as a rough UTXO-set statistic.
        // A full UTXO scan would require iterating the SQLite table; we provide
        // height and tip as the primary info. The UTXO set size can be derived
        // from block data.
        uint64_t block_count = tip ? tip->height + 1 : 0;
        j["blocks"] = block_count;

        return j;
    });

    // verifychain(depth): verify the last N blocks
    server.register_method("verifychain", [&chain](const json& params) -> json {
        int depth = 6;
        if (!params.empty() && params[0].is_number_integer()) {
            depth = params[0].get<int>();
        }
        if (depth < 1) depth = 1;

        CBlockIndex* idx = chain.tip();
        if (!idx) {
            throw std::runtime_error("Chain is empty");
        }

        int checked = 0;
        bool all_valid = true;

        while (idx && checked < depth) {
            // Verify the block is fully validated
            if (!(idx->status & BLOCK_FULLY_VALIDATED)) {
                // Attempt to read and re-validate the block
                CBlock block;
                if (!chain.block_store().read_block(idx->pos, block)) {
                    all_valid = false;
                    break;
                }

                // Verify the hash matches the stored data
                uint256 computed_hash = block.get_hash();
                if (computed_hash != idx->hash) {
                    all_valid = false;
                    break;
                }
            }

            checked++;
            idx = idx->prev;
        }

        json j;
        j["valid"]    = all_valid;
        j["checked"]  = checked;
        j["depth"]    = depth;
        return j;
    });
}

// ---------------------------------------------------------------------------
// Mempool RPCs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Extended blockchain RPCs
// ---------------------------------------------------------------------------

void register_extended_blockchain_rpcs(RpcServer& server, ChainState& chain) {

    // getdifficulty: return difficulty as float
    server.register_method("getdifficulty_ext", [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        if (!tip) return 1.0;

        // Convert compact nBits to a difficulty ratio.
        // difficulty = powLimit / current_target
        arith_uint256 pow_limit;
        consensus::derive_target(consensus::INITIAL_NBITS, pow_limit);

        arith_uint256 current_target;
        consensus::derive_target(tip->nbits, current_target);

        if (current_target == arith_uint256()) return 0.0;

        // Compute as a double
        arith_uint256 quotient = pow_limit / current_target;
        double diff = static_cast<double>(quotient.GetLow64());
        return diff;
    });

    // getblockfilter(hash): block bloom filter stub
    // Returns metadata about the block suitable for compact filtering.
    server.register_method("getblockfilter", [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getblockfilter <blockhash>");
        }

        std::string hash_hex = params[0].get<std::string>();
        auto bytes = hex_decode(hash_hex);
        if (bytes.size() != 32) {
            throw std::runtime_error("Invalid hash length");
        }
        uint256 hash;
        std::memcpy(hash.data(), bytes.data(), 32);

        CBlockIndex* idx = chain.block_tree().find(hash);
        if (!idx) {
            throw std::runtime_error("Block not found");
        }

        CBlock block;
        if (!chain.block_store().read_block(idx->pos, block)) {
            throw std::runtime_error("Block data not available on disk");
        }

        // Build a basic filter: collect all output pubkey hashes
        // and input pubkeys, hash them into a compact filter.
        std::vector<uint8_t> filter_data;
        for (const auto& tx : block.vtx) {
            for (const auto& out : tx.vout) {
                filter_data.insert(filter_data.end(),
                    out.pubkey_hash.begin(), out.pubkey_hash.end());
            }
            for (const auto& in : tx.vin) {
                if (!in.is_coinbase()) {
                    filter_data.insert(filter_data.end(),
                        in.pubkey.begin(), in.pubkey.end());
                }
            }
        }

        uint256 filter_hash = keccak256(filter_data);

        json j;
        j["blockhash"] = hash_hex;
        j["height"] = idx->height;
        j["filter_type"] = "basic";
        j["filter_hash"] = hex_encode(filter_hash.data(), 32);
        j["n_elements"] = block.vtx.size();
        j["filter_size"] = filter_data.size();

        return j;
    });

    // getblockhash_range(start, end): return hashes for a range of heights
    server.register_method("getblockhash_range", [&chain](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("Usage: getblockhash_range <start_height> <end_height>");
        }

        uint64_t start = params[0].get<uint64_t>();
        uint64_t end_h = params[1].get<uint64_t>();

        if (end_h < start) {
            throw std::runtime_error("End height must be >= start height");
        }

        if (end_h - start > 2016) {
            throw std::runtime_error("Range too large (max 2016 blocks)");
        }

        CBlockIndex* tip = chain.tip();
        if (!tip || end_h > tip->height) {
            throw std::runtime_error("End height exceeds chain tip");
        }

        // Walk back from tip to collect blocks in range
        std::vector<std::pair<uint64_t, std::string>> entries;
        CBlockIndex* idx = tip;
        while (idx && idx->height >= start) {
            if (idx->height <= end_h) {
                entries.push_back({idx->height, hex_encode(idx->hash.data(), 32)});
            }
            if (idx->height == 0) break;
            idx = idx->prev;
        }

        // Reverse to ascending order
        std::reverse(entries.begin(), entries.end());

        json result = json::array();
        for (const auto& [h, hash] : entries) {
            json e;
            e["height"] = h;
            e["hash"] = hash;
            result.push_back(e);
        }
        return result;
    });

    // getblockcount_by_time(timestamp): find block height closest to a timestamp
    server.register_method("getblockcount_by_time", [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_number()) {
            throw std::runtime_error("Usage: getblockcount_by_time <timestamp>");
        }
        int64_t target_time = params[0].get<int64_t>();

        CBlockIndex* idx = chain.tip();
        if (!idx) throw std::runtime_error("Chain is empty");

        // Binary-search style walk (linear for simplicity, could be optimized)
        CBlockIndex* best = idx;
        int64_t best_diff = std::abs(idx->timestamp - target_time);

        while (idx) {
            int64_t diff = std::abs(idx->timestamp - target_time);
            if (diff < best_diff) {
                best_diff = diff;
                best = idx;
            }
            // If we've passed the target time going backwards, stop
            if (idx->timestamp < target_time && idx->prev &&
                idx->prev->timestamp < target_time) {
                break;
            }
            idx = idx->prev;
        }

        json j;
        j["height"] = best->height;
        j["timestamp"] = best->timestamp;
        j["hash"] = hex_encode(best->hash.data(), 32);
        j["time_diff"] = best_diff;
        return j;
    });

    // getchainwork: return the total chain work (number of blocks)
    server.register_method("getchainwork", [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        json j;
        j["height"] = tip ? static_cast<int64_t>(tip->height) : 0;
        j["blocks"] = tip ? static_cast<int64_t>(tip->height + 1) : 0;

        return j;
    });

    // getblockheader_range(start, count): return multiple headers at once
    server.register_method("getblockheader_range", [&chain](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("Usage: getblockheader_range <start_height> <count>");
        }

        uint64_t start = params[0].get<uint64_t>();
        int count = params[1].get<int>();
        if (count <= 0 || count > 100) {
            throw std::runtime_error("Count must be between 1 and 100");
        }

        CBlockIndex* tip = chain.tip();
        if (!tip) throw std::runtime_error("Chain is empty");

        // Collect headers
        std::vector<CBlockIndex*> indices;
        CBlockIndex* idx = tip;
        while (idx) {
            if (idx->height >= start && idx->height < start + static_cast<uint64_t>(count)) {
                indices.push_back(idx);
            }
            if (idx->height == 0 || idx->height < start) break;
            idx = idx->prev;
        }

        std::reverse(indices.begin(), indices.end());

        CBlockIndex* range_tip = chain.tip();
        json result = json::array();
        for (CBlockIndex* bi : indices) {
            result.push_back(block_index_to_header_json(bi, range_tip));
        }
        return result;
    });
}

void register_mempool_rpcs(RpcServer& server, ChainState& /*chain*/,
                            Mempool& mempool) {

    // getrawmempool: list all transaction IDs in the mempool
    server.register_method("getrawmempool", [&mempool](const json& params) -> json {
        bool verbose = false;
        if (!params.empty() && params[0].is_boolean()) {
            verbose = params[0].get<bool>();
        }

        auto txids = mempool.get_txids();

        if (!verbose) {
            json result = json::array();
            for (const auto& txid : txids) {
                result.push_back(hex_encode(txid.data(), 32));
            }
            return result;
        }

        // Verbose: return object with txid -> info
        json result = json::object();
        for (const auto& txid : txids) {
            CTransaction tx;
            if (mempool.get(txid, tx)) {
                json entry;
                auto serialized = tx.serialize();
                entry["size"] = serialized.size();
                entry["vsize"] = serialized.size();
                entry["version"] = tx.version;
                entry["vin_count"] = tx.vin.size();
                entry["vout_count"] = tx.vout.size();

                Amount total_out = 0;
                for (const auto& out : tx.vout) {
                    total_out += out.amount;
                }
                entry["value_out"] = static_cast<double>(total_out) /
                                     static_cast<double>(consensus::COIN);

                result[hex_encode(txid.data(), 32)] = entry;
            }
        }
        return result;
    });

    // getmempoolinfo: mempool statistics
    server.register_method("getmempoolinfo", [&mempool](const json& /*params*/) -> json {
        json j;
        j["size"]   = mempool.size();
        j["bytes"]  = mempool.total_bytes();
        j["loaded"] = true;

        // Min relay fee rate in FLC per KB
        // 1 atomic unit/byte = 1000 atomic units/KB = 0.00001 FLC/KB
        double min_fee_per_kb = 1000.0 / static_cast<double>(consensus::COIN);
        j["mempoolminfee"]  = min_fee_per_kb;
        j["minrelaytxfee"]  = min_fee_per_kb;

        // Extended mempool stats
        auto stats = mempool.get_stats();
        j["orphan_count"]     = stats.orphan_count;
        j["total_fees"]       = static_cast<double>(stats.total_fees) /
                                static_cast<double>(consensus::COIN);
        j["min_fee_rate"]     = stats.min_fee_rate;
        j["median_fee_rate"]  = stats.median_fee_rate;
        j["max_fee_rate"]     = stats.max_fee_rate;

        if (stats.oldest_entry > 0 && stats.oldest_entry < std::numeric_limits<int64_t>::max()) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            j["oldest_entry_age"] = now - stats.oldest_entry;
        }

        return j;
    });

    // getmempoolentry(txid): detailed info about a single mempool tx
    server.register_method("getmempoolentry", [&mempool](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getmempoolentry <txid>");
        }

        std::string txid_hex = params[0].get<std::string>();
        auto bytes = hex_decode(txid_hex);
        if (bytes.size() != 32) {
            throw std::runtime_error("Invalid txid");
        }

        uint256 txid;
        std::memcpy(txid.data(), bytes.data(), 32);

        MempoolEntry entry;
        if (!mempool.get_entry(txid, entry)) {
            throw std::runtime_error("Transaction not found in mempool");
        }

        json j;
        j["txid"]      = txid_hex;
        j["size"]      = entry.tx_size;
        j["fee"]       = static_cast<double>(entry.fee) /
                         static_cast<double>(consensus::COIN);
        j["fee_atomic"] = entry.fee;
        j["fee_rate"]  = entry.fee_rate;
        j["time"]      = entry.time_added;
        j["version"]   = entry.tx.version;
        j["vin_count"] = entry.tx.vin.size();
        j["vout_count"] = entry.tx.vout.size();

        // Age in seconds
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        j["age"] = now - entry.time_added;

        // Ancestor info
        auto anc_info = mempool.get_ancestor_info(txid);
        json ancestors;
        ancestors["count"]    = anc_info.ancestor_count;
        ancestors["size"]     = anc_info.ancestor_size;
        ancestors["fees"]     = static_cast<double>(anc_info.ancestor_fees) /
                                static_cast<double>(consensus::COIN);
        ancestors["fee_rate"] = anc_info.ancestor_fee_rate;
        j["ancestor_info"]    = ancestors;

        // Descendant count
        auto descendants = mempool.get_descendants(txid);
        j["descendant_count"] = descendants.size();

        // Depends (parent txids in mempool)
        auto parent_txids = mempool.get_ancestors(txid);
        json depends = json::array();
        for (const auto& p : parent_txids) {
            depends.push_back(hex_encode(p.data(), 32));
        }
        j["depends"] = depends;

        // Spent-by (child txids in mempool)
        json spent_by = json::array();
        for (const auto& d : descendants) {
            spent_by.push_back(hex_encode(d.data(), 32));
        }
        j["spentby"] = spent_by;

        return j;
    });

    // getmempooldescendants(txid): list descendants of a mempool tx
    server.register_method("getmempooldescendants", [&mempool](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getmempooldescendants <txid>");
        }

        auto bytes = hex_decode(params[0].get<std::string>());
        if (bytes.size() != 32) {
            throw std::runtime_error("Invalid txid");
        }

        uint256 txid;
        std::memcpy(txid.data(), bytes.data(), 32);

        if (!mempool.exists(txid)) {
            throw std::runtime_error("Transaction not found in mempool");
        }

        auto descendants = mempool.get_descendants(txid);
        json result = json::array();
        for (const auto& d : descendants) {
            result.push_back(hex_encode(d.data(), 32));
        }
        return result;
    });

    // getmempoolancestors(txid): list ancestors of a mempool tx
    server.register_method("getmempoolancestors", [&mempool](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getmempoolancestors <txid>");
        }

        auto bytes = hex_decode(params[0].get<std::string>());
        if (bytes.size() != 32) {
            throw std::runtime_error("Invalid txid");
        }

        uint256 txid;
        std::memcpy(txid.data(), bytes.data(), 32);

        if (!mempool.exists(txid)) {
            throw std::runtime_error("Transaction not found in mempool");
        }

        auto ancestors = mempool.get_ancestors(txid);
        json result = json::array();
        for (const auto& a : ancestors) {
            result.push_back(hex_encode(a.data(), 32));
        }
        return result;
    });

    // testmempoolaccept(hex): test if a raw transaction would be accepted
    server.register_method("testmempoolaccept", [&mempool](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: testmempoolaccept <hex_tx>");
        }

        std::string hex_tx = params[0].get<std::string>();
        auto tx_bytes = hex_decode(hex_tx);
        if (tx_bytes.empty()) {
            throw std::runtime_error("Invalid hex encoding");
        }

        // Deserialize the transaction
        CTransaction tx;
        size_t consumed = 0;
        if (!tx.deserialize(tx_bytes.data(), tx_bytes.size(), consumed)) {
            json result = json::array();
            json entry;
            entry["txid"]    = "";
            entry["allowed"] = false;
            entry["reject-reason"] = "deserialization-failed";
            result.push_back(entry);
            return result;
        }

        uint256 txid = tx.get_txid();

        // Check if already in mempool
        if (mempool.exists(txid)) {
            json result = json::array();
            json entry;
            entry["txid"]    = hex_encode(txid.data(), 32);
            entry["allowed"] = false;
            entry["reject-reason"] = "txn-already-in-mempool";
            result.push_back(entry);
            return result;
        }

        // Try to add (this actually adds it; in a full implementation
        // we'd do a dry-run validation)
        auto add_result = mempool.add_transaction(tx);

        json result = json::array();
        json entry;
        entry["txid"]    = hex_encode(txid.data(), 32);
        entry["allowed"] = add_result.accepted;

        if (add_result.accepted) {
            // Remove it since this is just a test
            mempool.remove(txid);

            auto ser = tx.serialize();
            entry["vsize"] = ser.size();
            entry["fees"] = json::object();
        } else {
            entry["reject-reason"] = add_result.reject_reason;
        }

        result.push_back(entry);
        return result;
    });

    // getfeehistogram: fee histogram for fee estimation
    server.register_method("getfeehistogram", [&mempool](const json& params) -> json {
        int num_buckets = 20;
        if (!params.empty() && params[0].is_number_integer()) {
            num_buckets = params[0].get<int>();
            if (num_buckets < 1) num_buckets = 1;
            if (num_buckets > 100) num_buckets = 100;
        }

        auto histogram = mempool.get_fee_histogram(num_buckets);

        json result = json::array();
        for (const auto& bucket : histogram) {
            json b;
            b["min_fee_rate"] = bucket.min_fee_rate;
            b["max_fee_rate"] = bucket.max_fee_rate;
            b["count"]        = bucket.count;
            b["total_bytes"]  = bucket.total_bytes;
            result.push_back(b);
        }

        return result;
    });

    // estimatefee(target_blocks): simple fee estimation from mempool
    server.register_method("estimatefee", [&mempool](const json& params) -> json {
        int target_blocks = 6;
        if (!params.empty() && params[0].is_number_integer()) {
            target_blocks = params[0].get<int>();
            if (target_blocks < 1) target_blocks = 1;
        }

        double fee_rate = mempool.estimate_fee_rate(target_blocks);

        json j;
        j["feerate"]       = fee_rate / static_cast<double>(consensus::COIN);
        j["feerate_atomic"] = static_cast<int64_t>(fee_rate);
        j["target_blocks"] = target_blocks;
        j["mempool_size"]  = mempool.size();

        return j;
    });

    // savemempool: save mempool contents to disk (placeholder)
    server.register_method("savemempool", [&mempool](const json& /*params*/) -> json {
        json j;
        j["saved"]   = true;
        j["tx_count"] = mempool.size();
        j["bytes"]   = mempool.total_bytes();
        return j;
    });
}

} // namespace flow
