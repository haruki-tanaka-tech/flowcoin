// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "rest.h"
#include "chain/blockindex.h"
#include "chain/blockstore.h"
#include "chain/txindex.h"
#include "hash/keccak.h"
#include "util/strencodings.h"

#include "json/json.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <sstream>

namespace flow {

using json = nlohmann::json;

// ============================================================================
// RestResponse helpers
// ============================================================================

RestResponse RestResponse::json_ok(const std::vector<uint8_t>& body) {
    RestResponse r;
    r.status_code = 200;
    r.content_type = "application/json";
    r.body = body;
    return r;
}

RestResponse RestResponse::binary_ok(const std::vector<uint8_t>& body) {
    RestResponse r;
    r.status_code = 200;
    r.content_type = "application/octet-stream";
    r.body = body;
    return r;
}

RestResponse RestResponse::hex_ok(const std::vector<uint8_t>& body) {
    RestResponse r;
    r.status_code = 200;
    r.content_type = "text/plain";
    r.body = body;
    return r;
}

RestResponse RestResponse::error(int status_code, const std::string& message) {
    RestResponse r;
    r.status_code = status_code;
    r.content_type = "text/plain";
    r.body.assign(message.begin(), message.end());
    return r;
}

RestResponse RestResponse::not_found(const std::string& message) {
    return error(404, message);
}

RestResponse RestResponse::bad_request(const std::string& message) {
    return error(400, message);
}

// ============================================================================
// Format utilities
// ============================================================================

RestFormat parse_rest_format(const std::string& ext) {
    if (ext == "json") return RestFormat::JSON;
    if (ext == "bin") return RestFormat::BINARY;
    if (ext == "hex") return RestFormat::HEX;
    return RestFormat::JSON;
}

const char* rest_content_type(RestFormat fmt) {
    switch (fmt) {
        case RestFormat::JSON:   return "application/json";
        case RestFormat::BINARY: return "application/octet-stream";
        case RestFormat::HEX:    return "text/plain";
    }
    return "text/plain";
}

// ============================================================================
// RestServer
// ============================================================================

RestServer::RestServer(ChainState& chain, Mempool& mempool)
    : chain_(chain), mempool_(mempool) {
}

// ============================================================================
// Path parsing
// ============================================================================

std::vector<std::string> RestServer::split_path(const std::string& path) {
    std::vector<std::string> parts;
    std::string current;

    for (char c : path) {
        if (c == '/') {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }
    if (!current.empty()) {
        parts.push_back(current);
    }

    return parts;
}

std::pair<std::string, std::string> RestServer::split_extension(
    const std::string& filename) {
    auto dot = filename.rfind('.');
    if (dot == std::string::npos) {
        return {filename, "json"};  // default format
    }
    return {filename.substr(0, dot), filename.substr(dot + 1)};
}

RestServer::ParsedPath RestServer::parse_path(const std::string& path) {
    ParsedPath result;
    auto parts = split_path(path);

    // Expected: ["rest", endpoint, ...]
    if (parts.size() < 2 || parts[0] != "rest") {
        return result;
    }

    result.endpoint = parts[1];

    if (result.endpoint == "block") {
        if (parts.size() >= 3) {
            if (parts[2] == "notxdetails" && parts.size() >= 4) {
                result.endpoint = "block_notx";
                auto [name, ext] = split_extension(parts[3]);
                result.param1 = name;
                result.format = parse_rest_format(ext);
            } else {
                auto [name, ext] = split_extension(parts[2]);
                result.param1 = name;
                result.format = parse_rest_format(ext);
            }
            result.valid = true;
        }
    } else if (result.endpoint == "headers") {
        if (parts.size() >= 4) {
            result.param1 = parts[2];  // count
            auto [name, ext] = split_extension(parts[3]);
            result.param2 = name;  // hash
            result.format = parse_rest_format(ext);
            result.valid = true;
        }
    } else if (result.endpoint == "tx") {
        if (parts.size() >= 3) {
            auto [name, ext] = split_extension(parts[2]);
            result.param1 = name;
            result.format = parse_rest_format(ext);
            result.valid = true;
        }
    } else if (result.endpoint == "getutxos") {
        if (parts.size() >= 3) {
            auto [name, ext] = split_extension(parts[2]);
            result.param1 = name;
            result.format = parse_rest_format(ext);
            result.valid = true;
        }
    } else if (result.endpoint == "blockhashbyheight") {
        if (parts.size() >= 3) {
            auto [name, ext] = split_extension(parts[2]);
            result.param1 = name;
            result.format = parse_rest_format(ext);
            result.valid = true;
        }
    } else if (result.endpoint == "chaininfo") {
        result.valid = true;
        if (parts.size() >= 3) {
            auto [name, ext] = split_extension(parts[2]);
            (void)name;
            result.format = parse_rest_format(ext);
        }
    } else if (result.endpoint == "mempool") {
        if (parts.size() >= 3) {
            auto [name, ext] = split_extension(parts[2]);
            result.param1 = name;
            result.format = parse_rest_format(ext);
            result.valid = true;
        }
    }

    return result;
}

// ============================================================================
// Request routing
// ============================================================================

RestResponse RestServer::handle_request(const std::string& method,
                                         const std::string& path,
                                         const std::string& /*query*/) {
    if (method != "GET") {
        return RestResponse::error(405, "Method not allowed");
    }

    auto parsed = parse_path(path);
    if (!parsed.valid) {
        return RestResponse::not_found("Invalid REST path");
    }

    if (parsed.endpoint == "block") {
        return handle_block(parsed.param1, parsed.format, true);
    } else if (parsed.endpoint == "block_notx") {
        return handle_block(parsed.param1, parsed.format, false);
    } else if (parsed.endpoint == "headers") {
        int count = 1;
        try { count = std::stoi(parsed.param1); } catch (...) {}
        return handle_headers(count, parsed.param2, parsed.format);
    } else if (parsed.endpoint == "tx") {
        return handle_tx(parsed.param1, parsed.format);
    } else if (parsed.endpoint == "getutxos") {
        return handle_getutxos(parsed.param1, parsed.format);
    } else if (parsed.endpoint == "blockhashbyheight") {
        return handle_blockhashbyheight(parsed.param1, parsed.format);
    } else if (parsed.endpoint == "chaininfo") {
        return handle_chaininfo();
    } else if (parsed.endpoint == "mempool") {
        if (parsed.param1 == "info") {
            return handle_mempool_info();
        } else if (parsed.param1 == "contents") {
            return handle_mempool_contents();
        }
    }

    return RestResponse::not_found("Unknown endpoint");
}

// ============================================================================
// Hash utilities
// ============================================================================

std::string RestServer::hash_to_hex(const uint256& hash) {
    std::string hex;
    hex.reserve(64);
    static const char* digits = "0123456789abcdef";
    for (int i = 31; i >= 0; --i) {
        hex.push_back(digits[hash[i] >> 4]);
        hex.push_back(digits[hash[i] & 0xf]);
    }
    return hex;
}

bool RestServer::hex_to_hash(const std::string& hex, uint256& hash) {
    if (hex.size() != 64) return false;

    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    for (size_t i = 0; i < 32; ++i) {
        int h = hex_val(hex[i * 2]);
        int l = hex_val(hex[i * 2 + 1]);
        if (h < 0 || l < 0) return false;
        // Reverse byte order (display is big-endian, internal is little-endian)
        hash[31 - i] = static_cast<uint8_t>(h * 16 + l);
    }
    return true;
}

std::vector<uint8_t> RestServer::to_hex_bytes(
    const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result;
    result.reserve(data.size() * 2);
    static const char* digits = "0123456789abcdef";
    for (uint8_t b : data) {
        result.push_back(static_cast<uint8_t>(digits[b >> 4]));
        result.push_back(static_cast<uint8_t>(digits[b & 0xf]));
    }
    return result;
}

// ============================================================================
// /rest/block
// ============================================================================

RestResponse RestServer::handle_block(const std::string& hash_str,
                                       RestFormat format,
                                       bool with_tx_details) {
    uint256 hash;
    if (!hex_to_hash(hash_str, hash)) {
        return RestResponse::bad_request("Invalid block hash");
    }

    auto& tree = chain_.block_tree();
    auto* idx = tree.find(hash);
    if (!idx) {
        return RestResponse::not_found("Block not found");
    }

    CBlock block;
    if (!chain_.get_block_at_height(idx->height, block)) {
        return RestResponse::not_found("Block data not available");
    }

    switch (format) {
        case RestFormat::JSON:
            return RestResponse::json_ok(
                block_to_json(block, with_tx_details));

        case RestFormat::BINARY:
            return RestResponse::binary_ok(block.serialize());

        case RestFormat::HEX:
            return RestResponse::hex_ok(to_hex_bytes(block.serialize()));
    }

    return RestResponse::error(500, "Internal error");
}

// ============================================================================
// /rest/headers
// ============================================================================

RestResponse RestServer::handle_headers(int count,
                                         const std::string& hash_str,
                                         RestFormat format) {
    if (count < 1) count = 1;
    if (count > max_headers_) count = max_headers_;

    uint256 hash;
    if (!hex_to_hash(hash_str, hash)) {
        return RestResponse::bad_request("Invalid block hash");
    }

    auto& tree = chain_.block_tree();
    auto* idx = tree.find(hash);
    if (!idx) {
        return RestResponse::not_found("Block not found");
    }

    // Collect headers
    auto headers = chain_.get_headers_from(hash, count);

    switch (format) {
        case RestFormat::JSON: {
            json j = json::array();
            uint64_t tip_height = chain_.height();
            for (const auto& hdr : headers) {
                json hj;
                hj["hash"] = hash_to_hex(hdr.get_hash());
                hj["height"] = hdr.height;
                hj["version"] = hdr.version;
                hj["prev_hash"] = hash_to_hex(hdr.prev_hash);
                hj["merkle_root"] = hash_to_hex(hdr.merkle_root);
                hj["timestamp"] = hdr.timestamp;
                hj["nbits"] = hdr.nbits;
                hj["nonce"] = hdr.nonce;

                hj["confirmations"] = static_cast<int>(
                    tip_height >= hdr.height ?
                    tip_height - hdr.height + 1 : 0);
                j.push_back(hj);
            }
            std::string s = j.dump();
            return RestResponse::json_ok(
                std::vector<uint8_t>(s.begin(), s.end()));
        }

        case RestFormat::BINARY: {
            std::vector<uint8_t> data;
            for (const auto& hdr : headers) {
                auto hdr_data = hdr.serialize();
                data.insert(data.end(), hdr_data.begin(), hdr_data.end());
            }
            return RestResponse::binary_ok(data);
        }

        case RestFormat::HEX: {
            std::vector<uint8_t> data;
            for (const auto& hdr : headers) {
                auto hdr_data = hdr.serialize();
                data.insert(data.end(), hdr_data.begin(), hdr_data.end());
            }
            return RestResponse::hex_ok(to_hex_bytes(data));
        }
    }

    return RestResponse::error(500, "Internal error");
}

// ============================================================================
// /rest/tx
// ============================================================================

RestResponse RestServer::handle_tx(const std::string& hash_str,
                                    RestFormat format) {
    uint256 txid;
    if (!hex_to_hash(hash_str, txid)) {
        return RestResponse::bad_request("Invalid transaction hash");
    }

    // First check mempool
    CTransaction tx;
    uint256 block_hash;
    uint64_t block_height = 0;

    if (mempool_.get(txid, tx)) {
        block_hash.set_null();
        block_height = 0;
    } else {
        // Check transaction index
        auto* txindex = chain_.tx_index();
        if (!txindex) {
            return RestResponse::not_found(
                "Transaction not found (txindex not enabled)");
        }

        auto loc = txindex->find(txid);
        if (!loc.found) {
            return RestResponse::not_found("Transaction not found");
        }

        block_hash = loc.block_hash;
        block_height = loc.block_height;

        // Read the block to get the transaction
        CBlock block;
        if (!chain_.get_block_at_height(block_height, block)) {
            return RestResponse::not_found("Block data not available");
        }

        if (loc.tx_index < block.vtx.size()) {
            tx = block.vtx[loc.tx_index];
        } else {
            return RestResponse::not_found("Transaction not in block");
        }
    }

    switch (format) {
        case RestFormat::JSON:
            return RestResponse::json_ok(
                tx_to_json(tx, block_hash, block_height));

        case RestFormat::BINARY:
            return RestResponse::binary_ok(tx.serialize());

        case RestFormat::HEX:
            return RestResponse::hex_ok(to_hex_bytes(tx.serialize()));
    }

    return RestResponse::error(500, "Internal error");
}

// ============================================================================
// /rest/getutxos
// ============================================================================

RestResponse RestServer::handle_getutxos(const std::string& params,
                                          RestFormat format) {
    // Parse outpoints: "txid1-vout1/txid2-vout2/..."
    std::vector<std::pair<uint256, uint32_t>> outpoints;

    std::string remaining = params;
    while (!remaining.empty()) {
        auto slash = remaining.find('/');
        std::string entry = (slash == std::string::npos)
                            ? remaining
                            : remaining.substr(0, slash);
        remaining = (slash == std::string::npos)
                    ? ""
                    : remaining.substr(slash + 1);

        if (entry.empty()) continue;

        auto dash = entry.find('-');
        if (dash == std::string::npos || dash != 64) {
            continue;  // Invalid format
        }

        uint256 txid;
        if (!hex_to_hash(entry.substr(0, 64), txid)) continue;

        uint32_t vout = 0;
        try {
            vout = static_cast<uint32_t>(std::stoul(entry.substr(65)));
        } catch (...) { continue; }

        outpoints.emplace_back(txid, vout);

        if (static_cast<int>(outpoints.size()) >= max_utxos_) break;
    }

    // Look up UTXOs
    json j;
    j["chainHeight"] = chain_.height();

    auto* tip = chain_.tip();
    if (tip) {
        j["chaintipHash"] = hash_to_hex(tip->hash);
    }

    json bitmap = json::array();
    json utxos = json::array();

    for (const auto& [txid, vout] : outpoints) {
        UTXOEntry entry;
        bool found = chain_.utxo_set().get(txid, vout, entry);

        bitmap.push_back(found ? 1 : 0);

        if (found) {
            json u;
            u["txid"] = hash_to_hex(txid);
            u["vout"] = vout;
            u["value"] = entry.value;
            u["height"] = entry.height;
            u["coinbase"] = entry.is_coinbase;
            utxos.push_back(u);
        }
    }

    j["bitmap"] = bitmap;
    j["utxos"] = utxos;

    if (format == RestFormat::JSON) {
        std::string s = j.dump();
        return RestResponse::json_ok(
            std::vector<uint8_t>(s.begin(), s.end()));
    }

    // For binary/hex: serialize the response
    std::string s = j.dump();
    auto data = std::vector<uint8_t>(s.begin(), s.end());
    if (format == RestFormat::HEX) {
        return RestResponse::hex_ok(to_hex_bytes(data));
    }
    return RestResponse::binary_ok(data);
}

// ============================================================================
// /rest/blockhashbyheight
// ============================================================================

RestResponse RestServer::handle_blockhashbyheight(
    const std::string& height_str, RestFormat format) {
    uint64_t height = 0;
    try {
        height = std::stoull(height_str);
    } catch (...) {
        return RestResponse::bad_request("Invalid height");
    }

    if (height > chain_.height()) {
        return RestResponse::not_found("Height beyond chain tip");
    }

    auto* idx = chain_.get_block_index_at_height(height);
    if (!idx) {
        return RestResponse::not_found("Block not found at height");
    }

    std::string hash_hex = hash_to_hex(idx->hash);

    switch (format) {
        case RestFormat::JSON: {
            json j;
            j["blockhash"] = hash_hex;
            std::string s = j.dump();
            return RestResponse::json_ok(
                std::vector<uint8_t>(s.begin(), s.end()));
        }

        case RestFormat::BINARY:
            return RestResponse::binary_ok(
                std::vector<uint8_t>(idx->hash.begin(), idx->hash.end()));

        case RestFormat::HEX:
            return RestResponse::hex_ok(
                std::vector<uint8_t>(hash_hex.begin(), hash_hex.end()));
    }

    return RestResponse::error(500, "Internal error");
}

// ============================================================================
// /rest/chaininfo
// ============================================================================

RestResponse RestServer::handle_chaininfo() {
    json j;

    j["chain"] = "main";

    auto* tip = chain_.tip();
    if (tip) {
        j["blocks"] = tip->height;
        j["headers"] = tip->height;
        j["bestblockhash"] = hash_to_hex(tip->hash);
        j["difficulty"] = 1.0;  // Would compute from nbits
        j["time"] = tip->timestamp;
        j["mediantime"] = tip->timestamp;



        // train_steps removed from consensus
    } else {
        j["blocks"] = 0;
        j["headers"] = 0;
        j["bestblockhash"] = "";
    }

    // UTXO stats
    auto utxo_stats = chain_.get_utxo_stats();
    j["utxo_count"] = utxo_stats.count;
    j["total_supply"] = utxo_stats.total_value;

    // IBD status
    bool ibd = true;
    if (tip) {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        ibd = (now - tip->timestamp) > 86400;
    }
    j["initialblockdownload"] = ibd;

    // Mempool
    j["mempool_size"] = mempool_.size();
    j["mempool_bytes"] = mempool_.total_bytes();

    std::string s = j.dump();
    return RestResponse::json_ok(
        std::vector<uint8_t>(s.begin(), s.end()));
}

// ============================================================================
// /rest/mempool/info
// ============================================================================

RestResponse RestServer::handle_mempool_info() {
    auto stats = mempool_.get_stats();

    json j;
    j["loaded"] = true;
    j["size"] = stats.tx_count;
    j["bytes"] = stats.total_bytes;
    j["usage"] = stats.total_bytes;  // approximate memory usage
    j["total_fee"] = static_cast<double>(stats.total_fees) /
                     static_cast<double>(COIN);
    j["maxmempool"] = 300 * 1024 * 1024;  // 300 MB default
    j["mempoolminfee"] = stats.min_fee_rate;
    j["minrelaytxfee"] = 0.00001;  // 1 sat/byte in FLOW
    j["orphan_count"] = stats.orphan_count;

    std::string s = j.dump();
    return RestResponse::json_ok(
        std::vector<uint8_t>(s.begin(), s.end()));
}

// ============================================================================
// /rest/mempool/contents
// ============================================================================

RestResponse RestServer::handle_mempool_contents() {
    json j;

    auto entries = mempool_.get_all_entries();
    for (const auto& entry : entries) {
        std::string txid_hex = hash_to_hex(entry.txid);

        json tx_info;
        tx_info["vsize"] = entry.tx_size;
        tx_info["weight"] = entry.tx_size * 4;
        tx_info["fee"] = static_cast<double>(entry.fee) /
                         static_cast<double>(COIN);
        tx_info["time"] = entry.time_added;

        // Fee rate
        if (entry.tx_size > 0) {
            tx_info["fees"] = {
                {"base", static_cast<double>(entry.fee) /
                         static_cast<double>(COIN)}
            };
        }

        tx_info["vin_count"] = entry.tx.vin.size();
        tx_info["vout_count"] = entry.tx.vout.size();

        j[txid_hex] = tx_info;
    }

    std::string s = j.dump();
    return RestResponse::json_ok(
        std::vector<uint8_t>(s.begin(), s.end()));
}

// ============================================================================
// JSON serialization helpers
// ============================================================================

std::vector<uint8_t> RestServer::block_to_json(const CBlock& block,
                                                bool with_tx_details) {
    json j;

    uint256 block_hash = block.get_hash();
    j["hash"] = hash_to_hex(block_hash);
    j["height"] = block.height;
    j["version"] = block.version;
    j["prev_hash"] = hash_to_hex(block.prev_hash);
    j["merkle_root"] = hash_to_hex(block.merkle_root);
    j["training_hash"] = hash_to_hex(uint256{});
    j["dataset_hash"] = hash_to_hex(uint256{});
    j["timestamp"] = block.timestamp;
    j["nbits"] = block.nbits;
    j["nonce"] = block.nonce;






    // train_steps removed from consensus



    j["n_tx"] = block.vtx.size();
    j["size"] = block.get_block_size();
    j["weight"] = block.get_block_weight();

    // Confirmations
    uint64_t tip_height = chain_.height();
    j["confirmations"] = (tip_height >= block.height)
                         ? static_cast<int>(tip_height - block.height + 1) : 0;

    // Transactions
    json txs = json::array();
    for (const auto& tx : block.vtx) {
        if (with_tx_details) {
            json txj;
            txj["txid"] = hash_to_hex(tx.get_txid());
            txj["version"] = tx.version;
            txj["locktime"] = tx.locktime;
            txj["size"] = tx.get_serialize_size();

            json vin = json::array();
            for (const auto& in : tx.vin) {
                json inj;
                if (in.is_coinbase()) {
                    inj["coinbase"] = true;
                } else {
                    inj["txid"] = hash_to_hex(in.prevout.txid);
                    inj["vout"] = in.prevout.index;
                }
                vin.push_back(inj);
            }
            txj["vin"] = vin;

            json vout = json::array();
            for (size_t i = 0; i < tx.vout.size(); ++i) {
                json outj;
                outj["value"] = static_cast<double>(tx.vout[i].amount) /
                                static_cast<double>(COIN);
                outj["n"] = i;
                vout.push_back(outj);
            }
            txj["vout"] = vout;

            txs.push_back(txj);
        } else {
            txs.push_back(hash_to_hex(tx.get_txid()));
        }
    }
    j["tx"] = txs;

    std::string s = j.dump();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> RestServer::header_to_json(const CBlockHeader& header,
                                                  uint64_t height,
                                                  int confirmations) {
    json j;
    j["hash"] = hash_to_hex(header.get_hash());
    j["height"] = height;
    j["version"] = header.version;
    j["prev_hash"] = hash_to_hex(header.prev_hash);
    j["merkle_root"] = hash_to_hex(header.merkle_root);
    j["timestamp"] = header.timestamp;
    j["nbits"] = header.nbits;
    j["nonce"] = header.nonce;
    j["confirmations"] = confirmations;


    std::string s = j.dump();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> RestServer::tx_to_json(const CTransaction& tx,
                                              const uint256& block_hash,
                                              uint64_t block_height) {
    json j;
    j["txid"] = hash_to_hex(tx.get_txid());
    j["version"] = tx.version;
    j["locktime"] = tx.locktime;
    j["size"] = tx.get_serialize_size();

    if (!block_hash.is_null()) {
        j["blockhash"] = hash_to_hex(block_hash);
        j["blockheight"] = block_height;
        uint64_t tip = chain_.height();
        j["confirmations"] = (tip >= block_height)
                             ? static_cast<int>(tip - block_height + 1) : 0;
    } else {
        j["confirmations"] = 0;
    }

    json vin = json::array();
    for (const auto& in : tx.vin) {
        json inj;
        if (in.is_coinbase()) {
            inj["coinbase"] = true;
        } else {
            inj["txid"] = hash_to_hex(in.prevout.txid);
            inj["vout"] = in.prevout.index;
        }
        vin.push_back(inj);
    }
    j["vin"] = vin;

    json vout = json::array();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        json outj;
        outj["value"] = static_cast<double>(tx.vout[i].amount) /
                        static_cast<double>(COIN);
        outj["n"] = i;
        vout.push_back(outj);
    }
    j["vout"] = vout;

    std::string s = j.dump();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> RestServer::utxo_to_json(const uint256& txid,
                                                uint32_t vout,
                                                const UTXOEntry& entry) {
    json j;
    j["txid"] = hash_to_hex(txid);
    j["vout"] = vout;
    j["value"] = static_cast<double>(entry.value) /
                 static_cast<double>(COIN);
    j["height"] = entry.height;
    j["coinbase"] = entry.is_coinbase;

    std::string s = j.dump();
    return std::vector<uint8_t>(s.begin(), s.end());
}

// ============================================================================
// Additional REST query helpers
// ============================================================================

namespace rest_util {

/// Format a monetary amount as a string with 8 decimal places.
std::string format_amount(Amount amount) {
    bool negative = amount < 0;
    uint64_t abs_amount = negative ? static_cast<uint64_t>(-amount)
                                    : static_cast<uint64_t>(amount);
    uint64_t whole = abs_amount / 100000000ULL;
    uint64_t frac = abs_amount % 100000000ULL;

    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s%llu.%08llu",
                  negative ? "-" : "",
                  static_cast<unsigned long long>(whole),
                  static_cast<unsigned long long>(frac));
    return buf;
}

/// Parse a monetary amount from a string.
bool parse_amount(const std::string& str, Amount& amount) {
    if (str.empty()) return false;

    bool negative = false;
    size_t pos = 0;
    if (str[0] == '-') {
        negative = true;
        pos = 1;
    }

    // Find the decimal point
    auto dot = str.find('.', pos);
    if (dot == std::string::npos) {
        // No decimal point -- treat as whole coins
        try {
            uint64_t whole = std::stoull(str.substr(pos));
            amount = static_cast<Amount>(whole * 100000000ULL);
            if (negative) amount = -amount;
            return true;
        } catch (...) {
            return false;
        }
    }

    // Parse whole part
    uint64_t whole = 0;
    if (dot > pos) {
        try {
            whole = std::stoull(str.substr(pos, dot - pos));
        } catch (...) {
            return false;
        }
    }

    // Parse fractional part (up to 8 digits)
    std::string frac_str = str.substr(dot + 1);
    if (frac_str.size() > 8) return false;  // Too many decimal places

    // Pad to 8 digits
    while (frac_str.size() < 8) {
        frac_str += '0';
    }

    uint64_t frac = 0;
    try {
        frac = std::stoull(frac_str);
    } catch (...) {
        return false;
    }

    amount = static_cast<Amount>(whole * 100000000ULL + frac);
    if (negative) amount = -amount;
    return true;
}

/// URL-decode a string (handle %XX encoding).
std::string url_decode(const std::string& input) {
    std::string output;
    output.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size()) {
            auto hex_val = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
                return -1;
            };

            int h = hex_val(input[i + 1]);
            int l = hex_val(input[i + 2]);
            if (h >= 0 && l >= 0) {
                output += static_cast<char>(h * 16 + l);
                i += 2;
                continue;
            }
        } else if (input[i] == '+') {
            output += ' ';
            continue;
        }
        output += input[i];
    }

    return output;
}

/// Parse query string parameters into a map.
std::map<std::string, std::string> parse_query(const std::string& query) {
    std::map<std::string, std::string> params;
    if (query.empty()) return params;

    size_t pos = 0;
    while (pos < query.size()) {
        auto amp = query.find('&', pos);
        std::string pair = (amp == std::string::npos)
                           ? query.substr(pos)
                           : query.substr(pos, amp - pos);

        auto eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string key = url_decode(pair.substr(0, eq));
            std::string val = url_decode(pair.substr(eq + 1));
            params[key] = val;
        } else if (!pair.empty()) {
            params[url_decode(pair)] = "";
        }

        pos = (amp == std::string::npos) ? query.size() : amp + 1;
    }

    return params;
}

/// Validate that a hex string is a valid 64-character block/tx hash.
bool is_valid_hash_hex(const std::string& hex) {
    if (hex.size() != 64) return false;
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

/// Format a Unix timestamp as ISO 8601 date string.
std::string format_timestamp(int64_t timestamp) {
    time_t t = static_cast<time_t>(timestamp);
    struct tm tm_buf;
#ifdef _WIN32
    if (gmtime_s(&tm_buf, &t) != 0) return "unknown";
    struct tm* tm_result = &tm_buf;
#else
    struct tm* tm_result = gmtime_r(&t, &tm_buf);
    if (!tm_result) return "unknown";
#endif

    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm_result);
    return buf;
}

/// Calculate human-readable time difference.
std::string format_time_ago(int64_t timestamp) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    int64_t diff = now - timestamp;
    if (diff < 0) return "in the future";
    if (diff < 60) return std::to_string(diff) + " seconds ago";
    if (diff < 3600) return std::to_string(diff / 60) + " minutes ago";
    if (diff < 86400) return std::to_string(diff / 3600) + " hours ago";
    return std::to_string(diff / 86400) + " days ago";
}

/// Estimate the difficulty from compact target (nbits).
double difficulty_from_nbits(uint32_t nbits) {
    if (nbits == 0) return 0.0;

    int exp = static_cast<int>((nbits >> 24) & 0xFF);
    uint32_t mantissa = nbits & 0x007FFFFF;
    if (mantissa == 0) return 0.0;

    // Difficulty is relative to the maximum target
    // max_target = 0x00FFFFFF * 2^(8*(0x20-3)) = 0x00FFFFFF * 2^232
    // current_target = mantissa * 2^(8*(exp-3))
    // difficulty = max_target / current_target

    double target = static_cast<double>(mantissa) *
                    std::pow(256.0, exp - 3);
    double max_target = static_cast<double>(0x00FFFFFF) *
                        std::pow(256.0, 0x20 - 3);

    if (target == 0.0) return 0.0;
    return max_target / target;
}

/// Compute a CORS header map for REST responses.
std::map<std::string, std::string> cors_headers() {
    return {
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"},
        {"Access-Control-Max-Age", "86400"},
    };
}

/// Rate limiting state for REST API.
struct RateLimiter {
    static constexpr int MAX_REQUESTS_PER_MINUTE = 300;
    static constexpr int BURST_SIZE = 30;

    int64_t window_start = 0;
    int request_count = 0;

    bool allow_request() {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        // Reset window every 60 seconds
        if (now - window_start >= 60) {
            window_start = now;
            request_count = 0;
        }

        request_count++;
        return request_count <= MAX_REQUESTS_PER_MINUTE;
    }

    int remaining() const {
        return std::max(0, MAX_REQUESTS_PER_MINUTE - request_count);
    }
};

/// Compute ETag for cache validation.
std::string compute_etag(const std::vector<uint8_t>& data) {
    if (data.empty()) return "\"\"";
    uint256 hash = keccak256(data.data(), data.size());
    char buf[20];
    std::snprintf(buf, sizeof(buf), "\"%02x%02x%02x%02x%02x%02x%02x%02x\"",
                  hash[0], hash[1], hash[2], hash[3],
                  hash[4], hash[5], hash[6], hash[7]);
    return buf;
}

/// Build a JSON error response with standard fields.
std::vector<uint8_t> json_error(int code, const std::string& message) {
    json j;
    j["error"] = {
        {"code", code},
        {"message", message}
    };
    std::string s = j.dump();
    return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace rest_util

} // namespace flow
