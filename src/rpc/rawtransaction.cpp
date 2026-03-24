// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "rpc/rawtransaction.h"
#include "rpc/server.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "chain/blockstore.h"
#include "chain/utxo.h"
#include "consensus/params.h"
#include "crypto/bech32.h"
#include "hash/keccak.h"
#include "mempool/mempool.h"
#include "net/net.h"
#include "primitives/transaction.h"
#include "wallet/wallet.h"
#include "util/strencodings.h"

#include <cstring>
#include <stdexcept>

namespace flow {

// ---------------------------------------------------------------------------
// Helpers (local to this translation unit)
// ---------------------------------------------------------------------------

static std::string rtx_hash_to_hex(const uint256& h) {
    return hex_encode(h.data(), 32);
}

static uint256 rtx_hex_to_hash(const std::string& hex_str) {
    auto bytes = hex_decode(hex_str);
    if (bytes.size() != 32) {
        throw std::runtime_error("Invalid hash length (expected 64 hex chars)");
    }
    uint256 result;
    std::memcpy(result.data(), bytes.data(), 32);
    return result;
}

static json rtx_tx_to_json(const CTransaction& tx) {
    json j;
    j["txid"]     = rtx_hash_to_hex(tx.get_txid());
    j["version"]  = tx.version;
    j["locktime"] = tx.locktime;

    // Serialized size
    auto serialized = tx.serialize();
    j["size"] = serialized.size();
    j["hex"]  = hex_encode(serialized);

    json vin_arr = json::array();
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& in = tx.vin[i];
        json ij;
        if (in.is_coinbase()) {
            ij["coinbase"] = true;
        } else {
            ij["txid"]      = rtx_hash_to_hex(in.prevout.txid);
            ij["vout"]      = in.prevout.index;
            ij["pubkey"]    = hex_encode(in.pubkey.data(), 32);
            ij["signature"] = hex_encode(in.signature.data(), 64);
        }
        ij["sequence"] = i;
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
        vout_arr.push_back(oj);
    }
    j["vout"] = vout_arr;

    return j;
}

// ---------------------------------------------------------------------------
// Deserialize a transaction from a hex-encoded byte stream
// ---------------------------------------------------------------------------

static uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

static int64_t read_i64_le(const uint8_t* p) {
    uint64_t u = 0;
    for (int i = 0; i < 8; ++i) {
        u |= static_cast<uint64_t>(p[i]) << (i * 8);
    }
    int64_t result;
    std::memcpy(&result, &u, 8);
    return result;
}

static uint64_t read_varint(const uint8_t*& p, const uint8_t* end) {
    if (p >= end) throw std::runtime_error("Truncated varint");
    uint8_t first = *p++;
    if (first < 0xFD) return first;
    if (first == 0xFD) {
        if (p + 2 > end) throw std::runtime_error("Truncated varint");
        uint16_t v = static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
        p += 2;
        return v;
    }
    if (first == 0xFE) {
        if (p + 4 > end) throw std::runtime_error("Truncated varint");
        uint32_t v = read_u32_le(p);
        p += 4;
        return v;
    }
    // 0xFF
    if (p + 8 > end) throw std::runtime_error("Truncated varint");
    int64_t v = read_i64_le(p);
    p += 8;
    return static_cast<uint64_t>(v);
}

static CTransaction deserialize_tx(const std::vector<uint8_t>& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    if (data.size() < 4 + 1 + 1 + 8) {
        throw std::runtime_error("Transaction data too short");
    }

    CTransaction tx;
    tx.version = read_u32_le(p); p += 4;

    uint64_t vin_count = read_varint(p, end);
    if (vin_count > 10000) throw std::runtime_error("Too many inputs");

    for (uint64_t i = 0; i < vin_count; ++i) {
        if (p + 32 + 4 + 32 + 64 > end) throw std::runtime_error("Truncated input");
        CTxIn in;
        std::memcpy(in.prevout.txid.data(), p, 32); p += 32;
        in.prevout.index = read_u32_le(p); p += 4;
        std::memcpy(in.pubkey.data(), p, 32); p += 32;
        std::memcpy(in.signature.data(), p, 64); p += 64;
        tx.vin.push_back(in);
    }

    uint64_t vout_count = read_varint(p, end);
    if (vout_count > 10000) throw std::runtime_error("Too many outputs");

    for (uint64_t i = 0; i < vout_count; ++i) {
        if (p + 8 + 32 > end) throw std::runtime_error("Truncated output");
        int64_t amount = read_i64_le(p); p += 8;
        std::array<uint8_t, 32> pkh;
        std::memcpy(pkh.data(), p, 32); p += 32;
        tx.vout.emplace_back(amount, pkh);
    }

    if (p + 8 > end) throw std::runtime_error("Truncated locktime");
    tx.locktime = read_i64_le(p); p += 8;

    return tx;
}

// ---------------------------------------------------------------------------
// Search for a transaction in the chain by walking blocks
// ---------------------------------------------------------------------------

static bool find_tx_in_chain(ChainState& chain, const uint256& txid,
                              CTransaction& out_tx, uint64_t& out_height,
                              uint256& out_blockhash) {
    // Search from tip backwards (expensive for deep history, but correct)
    CBlockIndex* idx = chain.tip();

    // Limit search depth to prevent excessive scanning
    int depth = 0;
    constexpr int MAX_SEARCH_DEPTH = 10000;

    while (idx && depth < MAX_SEARCH_DEPTH) {
        CBlock block;
        if (chain.block_store().read_block(idx->pos, block)) {
            for (const auto& tx : block.vtx) {
                if (tx.get_txid() == txid) {
                    out_tx = tx;
                    out_height = idx->height;
                    out_blockhash = idx->hash;
                    return true;
                }
            }
        }
        idx = idx->prev;
        depth++;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void register_rawtx_rpcs(RpcServer& server, ChainState& chain,
                          Mempool& mempool, Wallet& wallet, NetManager& net) {

    // getrawtransaction(txid, verbose=false)
    // Look up a transaction in the mempool or chain.
    server.register_method("getrawtransaction",
        [&chain, &mempool](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getrawtransaction <txid> [verbose]");
        }

        uint256 txid = rtx_hex_to_hash(params[0].get<std::string>());
        bool verbose = false;
        if (params.size() > 1) {
            if (params[1].is_boolean()) verbose = params[1].get<bool>();
            else if (params[1].is_number_integer()) verbose = (params[1].get<int>() != 0);
        }

        // Check mempool first
        CTransaction tx;
        if (mempool.get(txid, tx)) {
            if (!verbose) {
                auto data = tx.serialize();
                return hex_encode(data);
            }
            json j = rtx_tx_to_json(tx);
            j["confirmations"] = 0;
            j["in_mempool"]    = true;
            return j;
        }

        // Search in chain
        uint64_t height = 0;
        uint256 blockhash;
        if (find_tx_in_chain(chain, txid, tx, height, blockhash)) {
            if (!verbose) {
                auto data = tx.serialize();
                return hex_encode(data);
            }
            json j = rtx_tx_to_json(tx);
            uint64_t tip_height = chain.height();
            j["confirmations"] = static_cast<int64_t>(tip_height - height + 1);
            j["blockhash"]     = rtx_hash_to_hex(blockhash);
            j["blockheight"]   = height;
            j["in_mempool"]    = false;
            return j;
        }

        throw std::runtime_error("Transaction not found");
    });

    // createrawtransaction(inputs, outputs)
    // inputs: [{"txid": "...", "vout": N}, ...]
    // outputs: {"address": amount, ...} or [{"address": amount}, ...]
    server.register_method("createrawtransaction",
        [](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error(
                "Usage: createrawtransaction "
                "[{\"txid\":\"...\",\"vout\":N},...] "
                "{\"address\":amount,...}");
        }

        const json& inputs_json = params[0];
        const json& outputs_json = params[1];

        if (!inputs_json.is_array()) {
            throw std::runtime_error("inputs must be a JSON array");
        }

        CTransaction tx;
        tx.version = 1;
        tx.locktime = 0;

        // Parse inputs
        for (const auto& inp : inputs_json) {
            if (!inp.contains("txid") || !inp.contains("vout")) {
                throw std::runtime_error("Each input must have 'txid' and 'vout'");
            }

            CTxIn txin;
            txin.prevout.txid = rtx_hex_to_hash(inp["txid"].get<std::string>());
            txin.prevout.index = inp["vout"].get<uint32_t>();
            txin.signature = {};
            txin.pubkey = {};
            tx.vin.push_back(txin);
        }

        // Parse outputs. Accept both object {"addr": amount} and array [{"addr": amount}]
        auto parse_output_entry = [&tx](const std::string& addr, double amount_flow) {
            if (amount_flow <= 0.0) {
                throw std::runtime_error("Output amount must be positive");
            }
            Amount amount_atomic = static_cast<Amount>(
                amount_flow * consensus::COIN + 0.5);

            auto decoded = bech32m_decode(addr);
            if (!decoded.valid || decoded.program.size() != 20) {
                throw std::runtime_error("Invalid address: " + addr);
            }

            std::array<uint8_t, 32> dest_pkh{};
            std::memcpy(dest_pkh.data(), decoded.program.data(), 20);

            tx.vout.emplace_back(amount_atomic, dest_pkh);
        };

        if (outputs_json.is_object()) {
            for (auto it = outputs_json.begin(); it != outputs_json.end(); ++it) {
                parse_output_entry(it.key(), it.value().get<double>());
            }
        } else if (outputs_json.is_array()) {
            for (const auto& item : outputs_json) {
                for (auto it = item.begin(); it != item.end(); ++it) {
                    parse_output_entry(it.key(), it.value().get<double>());
                }
            }
        } else {
            throw std::runtime_error("outputs must be a JSON object or array");
        }

        if (tx.vout.empty()) {
            throw std::runtime_error("At least one output is required");
        }

        // Return the hex-encoded unsigned transaction
        auto data = tx.serialize();
        return hex_encode(data);
    });

    // decoderawtransaction(hex): decode a hex-encoded transaction to JSON
    server.register_method("decoderawtransaction",
        [](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: decoderawtransaction <hex>");
        }

        std::string hex_tx = params[0].get<std::string>();
        auto bytes = hex_decode(hex_tx);
        if (bytes.empty()) {
            throw std::runtime_error("Invalid hex encoding");
        }

        CTransaction tx = deserialize_tx(bytes);
        return rtx_tx_to_json(tx);
    });

    // sendrawtransaction(hex): decode, validate, add to mempool, broadcast
    server.register_method("sendrawtransaction",
        [&mempool, &net](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: sendrawtransaction <hex>");
        }

        std::string hex_tx = params[0].get<std::string>();
        auto bytes = hex_decode(hex_tx);
        if (bytes.empty()) {
            throw std::runtime_error("Invalid hex encoding");
        }

        CTransaction tx = deserialize_tx(bytes);
        uint256 txid = tx.get_txid();

        // Add to mempool (validates inputs, signatures, fees)
        auto result = mempool.add_transaction(tx);
        if (!result.accepted) {
            throw std::runtime_error("Transaction rejected: " + result.reject_reason);
        }

        // Broadcast to all connected peers
        net.broadcast_transaction(tx);

        return rtx_hash_to_hex(txid);
    });

    // gettransaction(txid): get transaction with wallet-specific info
    server.register_method("gettransaction",
        [&chain, &mempool, &wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: gettransaction <txid>");
        }

        uint256 txid = rtx_hex_to_hash(params[0].get<std::string>());

        // Check mempool
        CTransaction tx;
        bool in_mempool = mempool.get(txid, tx);
        uint64_t height = 0;
        uint256 blockhash;

        if (!in_mempool) {
            if (!find_tx_in_chain(chain, txid, tx, height, blockhash)) {
                throw std::runtime_error("Transaction not found");
            }
        }

        json j = rtx_tx_to_json(tx);

        if (in_mempool) {
            j["confirmations"] = 0;
            j["in_mempool"]    = true;
        } else {
            uint64_t tip_height = chain.height();
            j["confirmations"] = static_cast<int64_t>(tip_height - height + 1);
            j["blockhash"]     = rtx_hash_to_hex(blockhash);
            j["blockheight"]   = height;
            j["in_mempool"]    = false;
        }

        // Compute wallet-specific amount (net received/sent)
        Amount received = 0;
        Amount sent_flag = 0;

        for (const auto& out : tx.vout) {
            // Check if this output belongs to our wallet by converting
            // pubkey_hash to an address and checking ownership
            // For efficiency we check the first 20 bytes against all addresses
            std::array<uint8_t, 32> pkh = out.pubkey_hash;
            // Build a temporary bech32m address from the first 20 bytes
            std::vector<uint8_t> program(pkh.data(), pkh.data() + 20);
            std::string out_addr = bech32m_encode("fl", 0, program);
            if (wallet.is_mine(out_addr)) {
                received += out.amount;
            }
        }

        for (const auto& in : tx.vin) {
            if (in.is_coinbase()) continue;
            std::string in_addr = pubkey_to_address(in.pubkey.data());
            if (wallet.is_mine(in_addr)) {
                sent_flag = 1;
            }
        }

        Amount net_amount;
        if (sent_flag > 0) {
            net_amount = received - tx.get_value_out();
        } else {
            net_amount = received;
        }

        j["amount"] = static_cast<double>(net_amount) /
                      static_cast<double>(consensus::COIN);

        return j;
    });
}

} // namespace flow
