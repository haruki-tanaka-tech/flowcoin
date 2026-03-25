// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "rpc/util.h"
#include "rpc/server.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "consensus/params.h"
#include "consensus/difficulty.h"
#include "consensus/reward.h"
#include "crypto/bech32.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "mempool/mempool.h"
#include "net/net.h"
#include "util/strencodings.h"
#include "version.h"
#include "wallet/wallet.h"

#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

namespace flow {

// Track the start time for uptime calculation
static std::chrono::steady_clock::time_point g_start_time;
static bool g_start_time_set = false;

// Log category state
static bool g_log_debug = false;
static bool g_log_net = true;
static bool g_log_mempool = true;
static bool g_log_rpc = true;
static bool g_log_wallet = true;

// ---------------------------------------------------------------------------
// Help text registry
// ---------------------------------------------------------------------------

struct RpcHelpEntry {
    std::string name;
    std::string category;
    std::string help;
};

static std::vector<RpcHelpEntry>& get_help_registry() {
    static std::vector<RpcHelpEntry> registry;
    return registry;
}

static void add_help(const std::string& name, const std::string& category,
                     const std::string& help) {
    get_help_registry().push_back({name, category, help});
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void register_util_rpcs(RpcServer& server, ChainState& chain,
                        Wallet& wallet, NetManager& net, Mempool& mempool) {

    if (!g_start_time_set) {
        g_start_time = std::chrono::steady_clock::now();
        g_start_time_set = true;
    }

    // -----------------------------------------------------------------------
    // help(method): show help for a method or list all methods
    // -----------------------------------------------------------------------
    add_help("help", "util",
        "help ( \"method\" )\n"
        "List all commands, or get help for a specific command.\n"
        "\nArguments:\n"
        "  method (string, optional) The command to get help on\n"
        "\nResult:\n"
        "  Help text for the method, or a list of all methods grouped by category.\n");

    server.register_method("help", [](const json& params) -> json {
        auto& registry = get_help_registry();

        if (!params.empty() && params[0].is_string()) {
            std::string method = params[0].get<std::string>();
            for (const auto& entry : registry) {
                if (entry.name == method) {
                    return entry.help;
                }
            }
            throw std::runtime_error("help: unknown method '" + method + "'");
        }

        // List all methods grouped by category
        std::map<std::string, std::vector<std::string>> categories;
        for (const auto& entry : registry) {
            categories[entry.category].push_back(entry.name);
        }

        std::string result;
        for (const auto& [cat, methods] : categories) {
            result += "== " + cat + " ==\n";
            for (const auto& m : methods) {
                result += "  " + m + "\n";
            }
            result += "\n";
        }
        return result;
    });

    // -----------------------------------------------------------------------
    // stop: shutdown the node
    // -----------------------------------------------------------------------
    add_help("stop", "util",
        "stop\n"
        "Request a graceful shutdown of the node.\n"
        "\nResult:\n"
        "  \"FlowCoin server stopping\"\n");

    server.register_method("stop", [](const json& /*params*/) -> json {
        // In production this would signal the event loop to stop.
        // For now, return the conventional response.
        return "FlowCoin server stopping";
    });

    // -----------------------------------------------------------------------
    // uptime: seconds since node started
    // -----------------------------------------------------------------------
    add_help("uptime", "util",
        "uptime\n"
        "Returns the total uptime of the server in seconds.\n"
        "\nResult:\n"
        "  n (numeric) The number of seconds the server has been running.\n");

    server.register_method("uptime", [](const json& /*params*/) -> json {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - g_start_time);
        return duration.count();
    });

    // -----------------------------------------------------------------------
    // getinfo: combined info (version, balance, height, connections, difficulty)
    // -----------------------------------------------------------------------
    add_help("getinfo", "util",
        "getinfo\n"
        "Returns an object containing various state info.\n"
        "\nResult:\n"
        "  {\n"
        "    \"version\": \"x.y.z\",\n"
        "    \"protocolversion\": n,\n"
        "    \"blocks\": n,\n"
        "    \"connections\": n,\n"
        "    \"difficulty\": n,\n"
        "    \"balance\": x.xxx,\n"
        "    \"chain\": \"main\"\n"
        "  }\n");

    server.register_method("getinfo", [&chain, &wallet, &net](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();

        json j;
        j["version"] = CLIENT_VERSION_STRING;
        j["protocolversion"] = consensus::PROTOCOL_VERSION;
        j["blocks"] = tip ? static_cast<int64_t>(tip->height) : 0;
        j["connections"] = static_cast<int64_t>(net.peer_count());
        j["difficulty"] = tip ? tip->nbits : consensus::INITIAL_NBITS;

        Amount balance = wallet.get_balance();
        j["balance"] = static_cast<double>(balance) /
                       static_cast<double>(consensus::COIN);
        j["chain"] = "main";
        j["encrypted"] = wallet.is_encrypted();
        j["locked"] = wallet.is_locked();

        auto now_epoch = std::chrono::steady_clock::now();
        auto uptime_s = std::chrono::duration_cast<std::chrono::seconds>(
            now_epoch - g_start_time);
        j["uptime"] = uptime_s.count();

        return j;
    });

    // -----------------------------------------------------------------------
    // validateaddress(addr): check address validity with details
    // -----------------------------------------------------------------------
    add_help("validateaddress", "util",
        "validateaddress \"address\"\n"
        "Return information about the given FlowCoin address.\n"
        "\nArguments:\n"
        "  address (string, required) The FlowCoin address to validate.\n"
        "\nResult:\n"
        "  { \"isvalid\": true/false, ... }\n");

    server.register_method("validateaddress", [&wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: validateaddress <address>");
        }
        std::string addr = params[0].get<std::string>();
        auto decoded = bech32m_decode(addr);

        json j;
        j["isvalid"] = decoded.valid;
        j["address"] = addr;

        if (decoded.valid) {
            j["hrp"] = decoded.hrp;
            j["witness_version"] = decoded.witness_version;
            j["witness_program"] = hex_encode(decoded.program.data(),
                                              decoded.program.size());
            j["ismine"] = wallet.is_mine(addr);

            bool is_mainnet = (decoded.hrp == consensus::MAINNET_HRP);
            bool is_testnet = (decoded.hrp == consensus::TESTNET_HRP);
            bool is_regtest = (decoded.hrp == consensus::REGTEST_HRP);
            j["network"] = is_mainnet ? "mainnet" :
                           is_testnet ? "testnet" :
                           is_regtest ? "regtest" : "unknown";

            j["scripttype"] = "witness_v0_keyhash";
        }

        return j;
    });

    // -----------------------------------------------------------------------
    // signmessagewithprivkey(privkey_hex, message): sign without wallet
    // -----------------------------------------------------------------------
    add_help("signmessagewithprivkey", "util",
        "signmessagewithprivkey \"privkey\" \"message\"\n"
        "Sign a message with a private key (does not require wallet).\n"
        "\nArguments:\n"
        "  privkey (string, required) The Ed25519 private key in hex.\n"
        "  message (string, required) The message to sign.\n"
        "\nResult:\n"
        "  \"signature\" (string) The hex-encoded signature+pubkey (96 bytes).\n");

    server.register_method("signmessagewithprivkey", [](const json& params) -> json {
        if (params.size() < 2 || !params[0].is_string() || !params[1].is_string()) {
            throw std::runtime_error("Usage: signmessagewithprivkey <privkey_hex> <message>");
        }

        std::string privkey_hex = params[0].get<std::string>();
        std::string message = params[1].get<std::string>();

        auto privkey_bytes = hex_decode(privkey_hex);
        if (privkey_bytes.size() != 32) {
            throw std::runtime_error("Private key must be 32 bytes (64 hex chars)");
        }

        std::array<uint8_t, 32> privkey;
        std::memcpy(privkey.data(), privkey_bytes.data(), 32);

        auto pubkey = derive_pubkey(privkey.data());

        // Create signed message preimage
        std::string preimage = "FlowCoin Signed Message:\n" + message;
        uint256 msg_hash = keccak256d(
            reinterpret_cast<const uint8_t*>(preimage.data()), preimage.size());

        auto sig = ed25519_sign(msg_hash.data(), 32, privkey.data(), pubkey.data());

        // Return signature (64) + pubkey (32) = 96 bytes hex
        std::vector<uint8_t> result(96);
        std::memcpy(result.data(), sig.data(), 64);
        std::memcpy(result.data() + 64, pubkey.data(), 32);

        return hex_encode(result);
    });

    // -----------------------------------------------------------------------
    // logging(include, exclude): set log categories
    // -----------------------------------------------------------------------
    add_help("logging", "util",
        "logging ( [\"include\",...] [\"exclude\",...] )\n"
        "Gets and sets the logging configuration.\n"
        "\nArguments:\n"
        "  include (array, optional) Categories to enable.\n"
        "  exclude (array, optional) Categories to disable.\n"
        "\nResult:\n"
        "  { category: true/false, ... }\n");

    server.register_method("logging", [](const json& params) -> json {
        // Process include list
        if (!params.empty() && params[0].is_array()) {
            for (const auto& cat : params[0]) {
                std::string c = cat.get<std::string>();
                if (c == "debug") g_log_debug = true;
                else if (c == "net") g_log_net = true;
                else if (c == "mempool") g_log_mempool = true;
                else if (c == "rpc") g_log_rpc = true;
                else if (c == "wallet") g_log_wallet = true;
                else if (c == "all" || c == "1") {
                    g_log_debug = g_log_net = g_log_mempool = g_log_rpc = g_log_wallet = true;
                }
            }
        }

        // Process exclude list
        if (params.size() > 1 && params[1].is_array()) {
            for (const auto& cat : params[1]) {
                std::string c = cat.get<std::string>();
                if (c == "debug") g_log_debug = false;
                else if (c == "net") g_log_net = false;
                else if (c == "mempool") g_log_mempool = false;
                else if (c == "rpc") g_log_rpc = false;
                else if (c == "wallet") g_log_wallet = false;
                else if (c == "none" || c == "0") {
                    g_log_debug = g_log_net = g_log_mempool = g_log_rpc = g_log_wallet = false;
                }
            }
        }

        json j;
        j["debug"] = g_log_debug;
        j["net"] = g_log_net;
        j["mempool"] = g_log_mempool;
        j["rpc"] = g_log_rpc;
        j["wallet"] = g_log_wallet;
        return j;
    });

    // -----------------------------------------------------------------------
    // echo(args...): echo back arguments (for testing)
    // -----------------------------------------------------------------------
    add_help("echo", "util",
        "echo \"arg1\" \"arg2\" ...\n"
        "Simply echo back the input arguments. Used for testing.\n"
        "\nResult:\n"
        "  The same arguments passed in.\n");

    server.register_method("echo", [](const json& params) -> json {
        return params;
    });

    // -----------------------------------------------------------------------
    // getmemoryinfo: memory usage statistics
    // -----------------------------------------------------------------------
    add_help("getmemoryinfo", "util",
        "getmemoryinfo\n"
        "Returns an object containing memory usage information.\n"
        "\nResult:\n"
        "  { \"rss\": n, \"utxo_cache\": n, \"mempool\": n, ... }\n");

    server.register_method("getmemoryinfo", [&chain, &mempool](const json& /*params*/) -> json {
        json j;

        // Read RSS from /proc/self/status on Linux
        long rss_kb = 0;
        std::ifstream status_file("/proc/self/status");
        if (status_file.is_open()) {
            std::string line;
            while (std::getline(status_file, line)) {
                if (line.substr(0, 6) == "VmRSS:") {
                    std::istringstream iss(line.substr(6));
                    iss >> rss_kb;
                    break;
                }
            }
        }

        j["rss_kb"] = rss_kb;
        j["rss_mb"] = static_cast<double>(rss_kb) / 1024.0;

        // Block tree size
        j["block_tree_entries"] = chain.block_tree().size();

        // Mempool stats
        j["mempool_size"] = mempool.size();
        j["mempool_bytes"] = mempool.total_bytes();

        // Chain height
        CBlockIndex* tip = chain.tip();
        j["chain_height"] = tip ? static_cast<int64_t>(tip->height) : 0;

        return j;
    });

    // -----------------------------------------------------------------------
    // getdifficulty: return current difficulty as a float
    // -----------------------------------------------------------------------
    add_help("getdifficulty", "blockchain",
        "getdifficulty\n"
        "Returns the proof-of-training difficulty as a float.\n"
        "\nResult:\n"
        "  n.nnn (numeric) The difficulty as a float.\n");

    server.register_method("getdifficulty", [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        if (!tip) {
            return 1.0;
        }

        // Convert compact nBits to a difficulty float.
        // difficulty = powLimit_target / current_target
        // powLimit is INITIAL_NBITS
        arith_uint256 pow_limit;
        consensus::derive_target(consensus::INITIAL_NBITS, pow_limit);

        arith_uint256 current_target;
        consensus::derive_target(tip->nbits, current_target);

        if (current_target == arith_uint256()) {
            return 0.0;
        }

        // Integer division for the main part, then convert to double
        arith_uint256 quotient = pow_limit / current_target;
        double diff = static_cast<double>(quotient.GetLow64());

        // For higher precision on targets that differ by less than 2^64
        arith_uint256 remainder = pow_limit % current_target;
        diff += static_cast<double>(remainder.GetLow64()) /
                static_cast<double>(current_target.GetLow64());

        return diff;
    });

    // -----------------------------------------------------------------------
    // getchaintips: list all known chain tips
    // -----------------------------------------------------------------------
    add_help("getchaintips", "blockchain",
        "getchaintips\n"
        "Return information about all known tips in the block tree.\n"
        "\nResult:\n"
        "  [ { \"height\": n, \"hash\": \"...\", \"status\": \"...\" }, ... ]\n");

    server.register_method("getchaintips", [&chain](const json& /*params*/) -> json {
        // Find all leaf nodes in the block tree (nodes with no children)
        // Since BlockTree doesn't expose iteration, we walk from the best tip
        // and report it as the active tip. A full implementation would track
        // all tips, but for now we report the best chain tip.
        CBlockIndex* tip = chain.tip();
        json result = json::array();

        if (tip) {
            json entry;
            entry["height"] = tip->height;
            entry["hash"] = hex_encode(tip->hash.data(), 32);
            entry["branchlen"] = 0;
            entry["status"] = "active";
            result.push_back(entry);
        }

        return result;
    });

    // -----------------------------------------------------------------------
    // getblockstats(height): block statistics
    // -----------------------------------------------------------------------
    add_help("getblockstats", "blockchain",
        "getblockstats height\n"
        "Compute per-block statistics for a given block height.\n"
        "\nArguments:\n"
        "  height (numeric, required) The block height.\n"
        "\nResult:\n"
        "  { \"height\": n, \"txs\": n, \"total_out\": n, ... }\n");

    server.register_method("getblockstats", [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_number()) {
            throw std::runtime_error("Usage: getblockstats <height>");
        }
        uint64_t target_height = params[0].get<uint64_t>();

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

        CBlock block;
        if (!chain.block_store().read_block(idx->pos, block)) {
            throw std::runtime_error("Block data not available on disk");
        }

        // Compute statistics
        int64_t total_out = 0;
        int64_t total_fee = 0;
        size_t total_size = block.delta_payload.size();
        int tx_count = static_cast<int>(block.vtx.size());
        int input_count = 0;
        int output_count = 0;

        for (const auto& tx : block.vtx) {
            auto ser = tx.serialize();
            total_size += ser.size();

            int64_t tx_total_out = tx.get_value_out();
            total_out += tx_total_out;

            input_count += static_cast<int>(tx.vin.size());
            output_count += static_cast<int>(tx.vout.size());
        }

        // Subsidy
        int64_t subsidy = consensus::compute_block_reward(idx->height);

        // The coinbase value minus subsidy approximates total fees
        if (!block.vtx.empty() && block.vtx[0].is_coinbase()) {
            int64_t coinbase_value = block.vtx[0].get_value_out();
            total_fee = coinbase_value - subsidy;
            if (total_fee < 0) total_fee = 0;
        }

        json j;
        j["height"]        = idx->height;
        j["hash"]          = hex_encode(idx->hash.data(), 32);
        j["time"]          = idx->timestamp;
        j["txs"]           = tx_count;
        j["inputs"]        = input_count;
        j["outputs"]       = output_count;
        j["total_out"]     = static_cast<double>(total_out) /
                             static_cast<double>(consensus::COIN);
        j["total_fee"]     = static_cast<double>(total_fee) /
                             static_cast<double>(consensus::COIN);
        j["subsidy"]       = static_cast<double>(subsidy) /
                             static_cast<double>(consensus::COIN);
        j["total_size"]    = total_size;
        j["val_loss"]      = idx->val_loss;
        j["d_model"]       = idx->d_model;
        j["n_layers"]      = idx->n_layers;
        // train_steps removed from consensus
        j["delta_size"]    = block.delta_payload.size();

        return j;
    });

    // -----------------------------------------------------------------------
    // waitfornewblock(timeout): long-poll for any new block
    // -----------------------------------------------------------------------
    add_help("waitfornewblock", "blockchain",
        "waitfornewblock ( timeout )\n"
        "Waits for a new block and returns useful info about the new block.\n"
        "\nArguments:\n"
        "  timeout (numeric, optional, default=0) Timeout in milliseconds (0 = no timeout).\n"
        "\nResult:\n"
        "  { \"hash\": \"...\", \"height\": n }\n");

    server.register_method("waitfornewblock", [&chain](const json& params) -> json {
        int timeout_ms = 0;
        if (!params.empty() && params[0].is_number()) {
            timeout_ms = params[0].get<int>();
        }

        CBlockIndex* initial_tip = chain.tip();
        uint64_t initial_height = initial_tip ? initial_tip->height : 0;

        auto start = std::chrono::steady_clock::now();

        // Poll until a new block arrives or timeout
        while (true) {
            CBlockIndex* current_tip = chain.tip();
            uint64_t current_height = current_tip ? current_tip->height : 0;

            if (current_height > initial_height) {
                json j;
                j["hash"] = hex_encode(current_tip->hash.data(), 32);
                j["height"] = current_tip->height;
                return j;
            }

            if (timeout_ms > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start);
                if (elapsed.count() >= timeout_ms) {
                    // Timeout: return current state
                    json j;
                    if (current_tip) {
                        j["hash"] = hex_encode(current_tip->hash.data(), 32);
                        j["height"] = current_tip->height;
                    } else {
                        j["hash"] = std::string(64, '0');
                        j["height"] = 0;
                    }
                    return j;
                }
            }

            // Sleep briefly to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // Safety: if no timeout was given, cap at 60 seconds
            if (timeout_ms == 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start);
                if (elapsed.count() >= 60) {
                    json j;
                    if (current_tip) {
                        j["hash"] = hex_encode(current_tip->hash.data(), 32);
                        j["height"] = current_tip->height;
                    } else {
                        j["hash"] = std::string(64, '0');
                        j["height"] = 0;
                    }
                    return j;
                }
            }
        }
    });

    // -----------------------------------------------------------------------
    // waitforblockheight(height, timeout): long-poll for a specific height
    // -----------------------------------------------------------------------
    add_help("waitforblockheight", "blockchain",
        "waitforblockheight height ( timeout )\n"
        "Waits for at least the given block height and returns info.\n"
        "\nArguments:\n"
        "  height  (numeric, required) The block height to wait for.\n"
        "  timeout (numeric, optional, default=0) Timeout in milliseconds.\n"
        "\nResult:\n"
        "  { \"hash\": \"...\", \"height\": n }\n");

    server.register_method("waitforblockheight", [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_number()) {
            throw std::runtime_error("Usage: waitforblockheight <height> [timeout_ms]");
        }
        uint64_t target_height = params[0].get<uint64_t>();
        int timeout_ms = 0;
        if (params.size() > 1 && params[1].is_number()) {
            timeout_ms = params[1].get<int>();
        }

        auto start = std::chrono::steady_clock::now();

        while (true) {
            CBlockIndex* tip = chain.tip();
            uint64_t current_height = tip ? tip->height : 0;

            if (current_height >= target_height) {
                json j;
                j["hash"] = hex_encode(tip->hash.data(), 32);
                j["height"] = tip->height;
                return j;
            }

            if (timeout_ms > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start);
                if (elapsed.count() >= timeout_ms) {
                    json j;
                    if (tip) {
                        j["hash"] = hex_encode(tip->hash.data(), 32);
                        j["height"] = tip->height;
                    } else {
                        j["hash"] = std::string(64, '0');
                        j["height"] = 0;
                    }
                    return j;
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            if (timeout_ms == 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start);
                if (elapsed.count() >= 60) {
                    json j;
                    if (tip) {
                        j["hash"] = hex_encode(tip->hash.data(), 32);
                        j["height"] = tip->height;
                    } else {
                        j["hash"] = std::string(64, '0');
                        j["height"] = 0;
                    }
                    return j;
                }
            }
        }
    });

    // -----------------------------------------------------------------------
    // Register help text for existing methods from other modules
    // -----------------------------------------------------------------------
    add_help("getblockcount", "blockchain", "getblockcount\nReturns the height of the most-work chain.\n");
    add_help("getbestblockhash", "blockchain", "getbestblockhash\nReturns the hash of the best (tip) block.\n");
    add_help("getblockhash", "blockchain", "getblockhash height\nReturns hash of block at given height.\n");
    add_help("getblock", "blockchain", "getblock \"hash\" ( verbosity )\nReturns block data.\n");
    add_help("getblockheader", "blockchain", "getblockheader \"hash\"\nReturns block header as JSON.\n");
    add_help("getblockchaininfo", "blockchain", "getblockchaininfo\nReturns chain state info.\n");
    add_help("gettxout", "blockchain", "gettxout \"txid\" n\nReturns details about an unspent tx output.\n");
    add_help("gettxoutsetinfo", "blockchain", "gettxoutsetinfo\nReturns UTXO set statistics.\n");
    add_help("verifychain", "blockchain", "verifychain ( depth )\nVerifies blockchain database.\n");
    add_help("getrawmempool", "blockchain", "getrawmempool ( verbose )\nReturns all txids in mempool.\n");
    add_help("getmempoolinfo", "blockchain", "getmempoolinfo\nReturns mempool details.\n");

    add_help("getnewaddress", "wallet", "getnewaddress\nGenerate a new receiving address.\n");
    add_help("getbalance", "wallet", "getbalance\nReturns wallet balance in FLOW.\n");
    add_help("listunspent", "wallet", "listunspent\nList wallet UTXOs.\n");
    add_help("sendtoaddress", "wallet", "sendtoaddress \"address\" amount\nSend coins.\n");
    add_help("listtransactions", "wallet", "listtransactions ( count skip )\nTransaction history.\n");
    add_help("importprivkey", "wallet", "importprivkey \"privkey_hex\"\nImport a private key.\n");
    add_help("dumpprivkey", "wallet", "dumpprivkey \"address\"\nExport private key for address.\n");
    add_help("dumpwallet", "wallet", "dumpwallet \"filepath\"\nDump all wallet keys.\n");
    add_help("importwallet", "wallet", "importwallet \"filepath\"\nImport keys from dump.\n");
    add_help("backupwallet", "wallet", "backupwallet \"destination\"\nBackup wallet file.\n");
    add_help("encryptwallet", "wallet", "encryptwallet \"passphrase\"\nEncrypt the wallet.\n");
    add_help("walletpassphrase", "wallet", "walletpassphrase \"passphrase\" timeout\nUnlock wallet.\n");
    add_help("walletlock", "wallet", "walletlock\nLock the wallet.\n");
    add_help("signmessage", "wallet", "signmessage \"address\" \"message\"\nSign a message.\n");
    add_help("verifymessage", "wallet", "verifymessage \"address\" \"sig\" \"msg\"\nVerify message.\n");
    add_help("getaddressinfo", "wallet", "getaddressinfo \"address\"\nAddress details.\n");
    add_help("listaddresses", "wallet", "listaddresses\nList all wallet addresses.\n");

    add_help("getblocktemplate", "mining", "getblocktemplate ( \"coinbase_addr\" )\nGet mining template.\n");
    add_help("submitblock", "mining", "submitblock \"hex\"\nSubmit a mined block.\n");
    add_help("getmininginfo", "mining", "getmininginfo\nMining status info.\n");

    add_help("getpeerinfo", "network", "getpeerinfo\nList connected peers.\n");
    add_help("getconnectioncount", "network", "getconnectioncount\nNumber of connections.\n");
    add_help("addnode", "network", "addnode \"ip:port\" ( \"add\"|\"remove\" )\nManage peers.\n");
    add_help("getnetworkinfo", "network", "getnetworkinfo\nNetwork state info.\n");

    add_help("getrawtransaction", "rawtx", "getrawtransaction \"txid\" ( verbose )\nGet raw tx.\n");
    add_help("createrawtransaction", "rawtx", "createrawtransaction [{\"txid\":\"...\",\"vout\":n},...] {\"addr\":amt,...}\nCreate unsigned tx.\n");
    add_help("decoderawtransaction", "rawtx", "decoderawtransaction \"hex\"\nDecode raw tx hex.\n");
    add_help("sendrawtransaction", "rawtx", "sendrawtransaction \"hex\"\nSubmit raw tx.\n");
    add_help("gettransaction", "rawtx", "gettransaction \"txid\"\nGet tx with wallet info.\n");

    add_help("gettraininginfo", "training", "gettraininginfo\nModel training info from tip.\n");
    add_help("getmodelweights", "training", "getmodelweights\nGet tip block delta payload.\n");
    add_help("getmodelhash", "training", "getmodelhash\nGet model state hashes.\n");
    add_help("getdeltapayload", "training", "getdeltapayload \"blockhash\"\nGet delta from block.\n");
    add_help("getgrowthschedule", "training", "getgrowthschedule ( height )\nModel dims at height.\n");
    add_help("getvalidationdata", "training", "getvalidationdata\nEvaluation dataset metadata.\n");

    // -----------------------------------------------------------------------
    // createmultisig(n, pubkeys): create a multisig address (informational)
    // -----------------------------------------------------------------------
    add_help("createmultisig", "util",
        "createmultisig nrequired [\"key\",...]\n"
        "Creates a multi-signature address.\n"
        "\nArguments:\n"
        "  nrequired (numeric, required) The number of required signatures.\n"
        "  keys      (array, required) Array of hex-encoded public keys.\n"
        "\nResult:\n"
        "  { \"address\": \"...\", \"redeemScript\": \"...\" }\n"
        "\nNote: FlowCoin uses Ed25519 which does not natively support\n"
        "multisig. This creates a threshold address for informational purposes.\n");

    server.register_method("createmultisig", [](const json& params) -> json {
        if (params.size() < 2 || !params[0].is_number() || !params[1].is_array()) {
            throw std::runtime_error(
                "Usage: createmultisig <nrequired> [\"pubkey1\",\"pubkey2\",...]");
        }

        int n_required = params[0].get<int>();
        const auto& keys_json = params[1];

        if (n_required < 1) {
            throw std::runtime_error("nrequired must be at least 1");
        }
        if (keys_json.empty()) {
            throw std::runtime_error("At least one public key is required");
        }
        if (n_required > static_cast<int>(keys_json.size())) {
            throw std::runtime_error("nrequired cannot exceed the number of keys");
        }

        // Collect and validate public keys
        std::vector<std::array<uint8_t, 32>> pubkeys;
        for (const auto& key_json : keys_json) {
            if (!key_json.is_string()) {
                throw std::runtime_error("Each key must be a hex string");
            }
            std::string hex_key = key_json.get<std::string>();
            auto key_bytes = hex_decode(hex_key);
            if (key_bytes.size() != 32) {
                throw std::runtime_error("Each public key must be 32 bytes (64 hex chars)");
            }
            std::array<uint8_t, 32> pk;
            std::memcpy(pk.data(), key_bytes.data(), 32);
            pubkeys.push_back(pk);
        }

        // Create a deterministic multisig script by hashing n + sorted pubkeys.
        // The "redeem script" is: keccak256(n || sorted_pubkeys)
        // The "address" is derived from this hash.
        std::sort(pubkeys.begin(), pubkeys.end());

        std::vector<uint8_t> script_data;
        script_data.push_back(static_cast<uint8_t>(n_required));
        script_data.push_back(static_cast<uint8_t>(pubkeys.size()));
        for (const auto& pk : pubkeys) {
            script_data.insert(script_data.end(), pk.begin(), pk.end());
        }

        uint256 script_hash = keccak256(script_data);

        // Use the first 20 bytes as a witness program
        std::vector<uint8_t> program(script_hash.data(), script_hash.data() + 20);
        std::string address = bech32m_encode("fl", 0, program);

        json j;
        j["address"] = address;
        j["redeemScript"] = hex_encode(script_data);
        j["descriptor"] = "multi(" + std::to_string(n_required) + ",...)";
        j["nrequired"] = n_required;
        j["n_total"] = static_cast<int>(pubkeys.size());
        return j;
    });

    // -----------------------------------------------------------------------
    // verifymessage_ext(address, signature, message): extended verify
    // -----------------------------------------------------------------------
    add_help("verifymessage_ext", "util",
        "verifymessage_ext \"address\" \"signature_hex\" \"message\"\n"
        "Verify a signed message and return detailed verification info.\n"
        "\nArguments:\n"
        "  address   (string, required) The address that signed.\n"
        "  signature (string, required) Hex-encoded sig+pubkey (96 bytes).\n"
        "  message   (string, required) The original message.\n"
        "\nResult:\n"
        "  { \"valid\": true/false, ... }\n");

    server.register_method("verifymessage_ext", [](const json& params) -> json {
        if (params.size() < 3) {
            throw std::runtime_error(
                "Usage: verifymessage_ext <address> <signature_hex> <message>");
        }
        std::string addr = params[0].get<std::string>();
        std::string sig_hex = params[1].get<std::string>();
        std::string message = params[2].get<std::string>();

        auto decoded = bech32m_decode(addr);
        if (!decoded.valid || decoded.program.size() != 20) {
            throw std::runtime_error("Invalid address");
        }

        auto sig_bytes = hex_decode(sig_hex);
        if (sig_bytes.size() != 96) {
            throw std::runtime_error("Signature must be 96 bytes hex "
                                      "(64-byte Ed25519 sig + 32-byte pubkey)");
        }

        std::array<uint8_t, 64> signature;
        std::array<uint8_t, 32> pubkey;
        std::memcpy(signature.data(), sig_bytes.data(), 64);
        std::memcpy(pubkey.data(), sig_bytes.data() + 64, 32);

        // Verify pubkey matches address
        std::string derived_addr = pubkey_to_address(pubkey.data());
        bool addr_match = (derived_addr == addr);

        // Reconstruct signed message preimage
        std::string preimage = "FlowCoin Signed Message:\n" + message;
        uint256 msg_hash = keccak256d(
            reinterpret_cast<const uint8_t*>(preimage.data()),
            preimage.size());

        bool sig_valid = ed25519_verify(msg_hash.data(), 32,
                                         pubkey.data(), signature.data());

        json j;
        j["valid"] = addr_match && sig_valid;
        j["address_match"] = addr_match;
        j["signature_valid"] = sig_valid;
        j["address"] = addr;
        j["derived_address"] = derived_addr;
        j["pubkey"] = hex_encode(pubkey.data(), 32);
        j["message_hash"] = hex_encode(msg_hash.data(), 32);

        return j;
    });

    // -----------------------------------------------------------------------
    // getindexinfo: information about enabled indices
    // -----------------------------------------------------------------------
    add_help("getindexinfo", "util",
        "getindexinfo\n"
        "Returns information about the status of all indices.\n"
        "\nResult:\n"
        "  { \"txindex\": { ... }, \"blockfilter\": { ... } }\n");

    server.register_method("getindexinfo", [&chain](const json& /*params*/) -> json {
        json j;

        // Transaction index info
        json txindex_info;
        txindex_info["enabled"] = (chain.tx_index() != nullptr);
        if (chain.tx_index()) {
            CBlockIndex* tip = chain.tip();
            txindex_info["synced_height"] = tip ? static_cast<int64_t>(tip->height) : 0;
            txindex_info["best_block"] = tip ? hex_encode(tip->hash.data(), 32) : "";
        }
        j["txindex"] = txindex_info;

        // Block filter info (not implemented, but report status)
        json filter_info;
        filter_info["enabled"] = false;
        filter_info["type"] = "basic";
        j["blockfilter"] = filter_info;

        return j;
    });

    // -----------------------------------------------------------------------
    // getdescriptorinfo(desc): analyze a descriptor string
    // -----------------------------------------------------------------------
    add_help("getdescriptorinfo", "util",
        "getdescriptorinfo \"descriptor\"\n"
        "Analyzes a descriptor string.\n"
        "\nArguments:\n"
        "  descriptor (string, required) The descriptor to analyze.\n"
        "\nResult:\n"
        "  { \"descriptor\": \"...\", \"isrange\": false, ... }\n");

    server.register_method("getdescriptorinfo", [](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getdescriptorinfo <descriptor>");
        }
        std::string desc = params[0].get<std::string>();

        json j;
        j["descriptor"] = desc;

        // Parse basic descriptor types
        if (desc.find("pkh(") != std::string::npos) {
            j["type"] = "pkh";
            j["isrange"] = false;
            j["issolvable"] = true;
        } else if (desc.find("multi(") != std::string::npos) {
            j["type"] = "multi";
            j["isrange"] = false;
            j["issolvable"] = true;
        } else if (desc.find("addr(") != std::string::npos) {
            j["type"] = "addr";
            j["isrange"] = false;
            j["issolvable"] = false;
        } else {
            j["type"] = "unknown";
            j["isrange"] = false;
            j["issolvable"] = false;
        }

        // Compute checksum of the descriptor
        uint256 desc_hash = keccak256(
            reinterpret_cast<const uint8_t*>(desc.data()), desc.size());
        std::string checksum = hex_encode(desc_hash.data(), 4);
        j["checksum"] = checksum;

        return j;
    });

    // -----------------------------------------------------------------------
    // deriveaddresses(descriptor, range): derive addresses from descriptor
    // -----------------------------------------------------------------------
    add_help("deriveaddresses", "util",
        "deriveaddresses \"descriptor\" ( range )\n"
        "Derives one or more addresses from a descriptor.\n"
        "\nArguments:\n"
        "  descriptor (string, required) The descriptor.\n"
        "  range      (array, optional)  [begin, end] range for ranged descriptors.\n"
        "\nResult:\n"
        "  [\"address\", ...]\n");

    server.register_method("deriveaddresses", [](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: deriveaddresses <descriptor> [range]");
        }
        std::string desc = params[0].get<std::string>();

        // Simple implementation: if descriptor is "pkh(hex_pubkey)",
        // derive the address from the pubkey
        json result = json::array();

        // Try to extract a public key from pkh(...)
        auto start = desc.find("pkh(");
        if (start != std::string::npos) {
            size_t key_start = start + 4;
            auto end_pos = desc.find(')', key_start);
            if (end_pos != std::string::npos) {
                std::string hex_key = desc.substr(key_start, end_pos - key_start);
                auto key_bytes = hex_decode(hex_key);
                if (key_bytes.size() == 32) {
                    std::string addr = pubkey_to_address(key_bytes.data());
                    result.push_back(addr);
                    return result;
                }
            }
        }

        // Try addr(address)
        auto addr_start = desc.find("addr(");
        if (addr_start != std::string::npos) {
            size_t a_start = addr_start + 5;
            auto end_pos = desc.find(')', a_start);
            if (end_pos != std::string::npos) {
                std::string addr = desc.substr(a_start, end_pos - a_start);
                result.push_back(addr);
                return result;
            }
        }

        throw std::runtime_error("Cannot derive addresses from descriptor: " + desc);
    });

    // -----------------------------------------------------------------------
    // Register help for new methods
    // -----------------------------------------------------------------------
    add_help("setlabel", "wallet", "setlabel \"address\" \"label\"\nSet address label.\n");
    add_help("getlabel", "wallet", "getlabel \"address\"\nGet address label.\n");
    add_help("listlabels", "wallet", "listlabels\nList all labels.\n");
    add_help("getaddressesbylabel", "wallet", "getaddressesbylabel \"label\"\nGet addresses by label.\n");
    add_help("getwalletinfo", "wallet", "getwalletinfo\nWallet status info.\n");
    add_help("rescanblockchain", "wallet", "rescanblockchain ( start_height )\nRescan for wallet txs.\n");
    add_help("keypoolrefill", "wallet", "keypoolrefill ( size )\nRefill key pool.\n");
    add_help("listreceivedbyaddress", "wallet", "listreceivedbyaddress ( minconf include_empty )\nList received.\n");
    add_help("settxfee", "wallet", "settxfee amount\nSet tx fee rate.\n");
    add_help("gettransactiondetails", "wallet", "gettransactiondetails \"txid\"\nDetailed tx info.\n");
    add_help("getdifficulty_ext", "blockchain", "getdifficulty_ext\nExtended difficulty info.\n");
    add_help("getblockfilter", "blockchain", "getblockfilter \"hash\"\nBlock filter.\n");
    add_help("getblockhash_range", "blockchain", "getblockhash_range start end\nHash range.\n");
    add_help("getblockcount_by_time", "blockchain", "getblockcount_by_time timestamp\nFind block by time.\n");
    add_help("getchainwork", "blockchain", "getchainwork\nChain work statistics.\n");
    add_help("getblockheader_range", "blockchain", "getblockheader_range start count\nMultiple headers.\n");
    add_help("createmultisig", "util", "createmultisig n [keys]\nCreate multisig address.\n");
    add_help("verifymessage_ext", "util", "verifymessage_ext addr sig msg\nExtended verify.\n");
    add_help("getindexinfo", "util", "getindexinfo\nIndex status.\n");
    add_help("getdescriptorinfo", "util", "getdescriptorinfo desc\nAnalyze descriptor.\n");
    add_help("deriveaddresses", "util", "deriveaddresses desc [range]\nDerive addresses.\n");
}

} // namespace flow
