// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "rpc/register.h"
#include "rpc/server.h"
#include "rpc/blockchain.h"
#include "rpc/mining.h"
#include "rpc/net.h"
#include "rpc/rawtransaction.h"
#include "rpc/util.h"
#include "rpc/wallet.h"
#include "rpc/debug.h"

#include "chain/chainstate.h"
#include "mempool/mempool.h"
#include "net/net.h"
#include "wallet/wallet.h"

#include <algorithm>
#include <mutex>
#include <sstream>

namespace flow {

// ---------------------------------------------------------------------------
// Help registry (global singleton)
// ---------------------------------------------------------------------------

namespace {

struct HelpRegistry {
    std::mutex mutex;
    std::vector<RpcMethodHelp> entries;

    static HelpRegistry& instance() {
        static HelpRegistry reg;
        return reg;
    }
};

} // anonymous namespace

void register_help(const RpcMethodHelp& help) {
    auto& reg = HelpRegistry::instance();
    std::lock_guard<std::mutex> lock(reg.mutex);

    // Update if already exists
    for (auto& entry : reg.entries) {
        if (entry.name == help.name) {
            entry = help;
            return;
        }
    }
    reg.entries.push_back(help);
}

bool get_method_help(const std::string& name, RpcMethodHelp& help) {
    auto& reg = HelpRegistry::instance();
    std::lock_guard<std::mutex> lock(reg.mutex);

    for (const auto& entry : reg.entries) {
        if (entry.name == name) {
            help = entry;
            return true;
        }
    }
    return false;
}

std::map<std::string, std::vector<std::string>> list_methods_by_category() {
    auto& reg = HelpRegistry::instance();
    std::lock_guard<std::mutex> lock(reg.mutex);

    std::map<std::string, std::vector<std::string>> result;
    for (const auto& entry : reg.entries) {
        result[entry.category].push_back(entry.name);
    }

    // Sort methods within each category
    for (auto& [cat, methods] : result) {
        std::sort(methods.begin(), methods.end());
    }

    return result;
}

std::vector<std::string> list_all_methods() {
    auto& reg = HelpRegistry::instance();
    std::lock_guard<std::mutex> lock(reg.mutex);

    std::vector<std::string> result;
    result.reserve(reg.entries.size());
    for (const auto& entry : reg.entries) {
        result.push_back(entry.name);
    }
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<RpcMethodHelp> get_category_help(const std::string& category) {
    auto& reg = HelpRegistry::instance();
    std::lock_guard<std::mutex> lock(reg.mutex);

    std::vector<RpcMethodHelp> result;
    for (const auto& entry : reg.entries) {
        if (entry.category == category) {
            result.push_back(entry);
        }
    }
    return result;
}

size_t help_entry_count() {
    auto& reg = HelpRegistry::instance();
    std::lock_guard<std::mutex> lock(reg.mutex);
    return reg.entries.size();
}

std::string format_help(const RpcMethodHelp& help) {
    std::ostringstream ss;
    ss << help.name << "\n";
    ss << help.summary << "\n";

    if (!help.params.empty()) {
        ss << "\nArguments:\n" << help.params << "\n";
    }
    if (!help.result.empty()) {
        ss << "\nResult:\n" << help.result << "\n";
    }
    if (!help.examples.empty()) {
        ss << "\nExamples:\n" << help.examples << "\n";
    }

    return ss.str();
}

std::string format_help_all() {
    auto categories = list_methods_by_category();

    std::ostringstream ss;
    for (const auto& [cat, methods] : categories) {
        ss << "== " << cat << " ==\n";
        for (const auto& name : methods) {
            RpcMethodHelp help;
            if (get_method_help(name, help)) {
                ss << "  " << name;
                if (!help.summary.empty()) {
                    ss << " - " << help.summary;
                }
                ss << "\n";
            } else {
                ss << "  " << name << "\n";
            }
        }
        ss << "\n";
    }

    return ss.str();
}

// ---------------------------------------------------------------------------
// Register built-in help entries for core methods
// ---------------------------------------------------------------------------

static void register_core_help_entries() {
    // Blockchain
    register_help({"getblockcount", "blockchain",
        "Returns the height of the most-work fully-validated chain.",
        "None",
        "n (numeric) The current block count",
        "flowcoin-cli getblockcount"});

    register_help({"getbestblockhash", "blockchain",
        "Returns the hash of the best (tip) block in the most-work chain.",
        "None",
        "\"hex\" (string) The block hash, hex-encoded",
        "flowcoin-cli getbestblockhash"});

    register_help({"getblockhash", "blockchain",
        "Returns hash of block in best-block-chain at height provided.",
        "  height (numeric, required) The height index",
        "\"hex\" (string) The block hash",
        "flowcoin-cli getblockhash 1000"});

    register_help({"getblock", "blockchain",
        "Returns information about a block by hash.",
        "  blockhash (string, required) The block hash\n"
        "  verbosity (numeric, optional, default=1) 0=hex, 1=json with txids, 2=json with txs",
        "{ ... } (object) A block object",
        "flowcoin-cli getblock \"00000000...\""});

    register_help({"getblockheader", "blockchain",
        "Returns the block header for the given hash.",
        "  blockhash (string, required) The block hash",
        "{ ... } (object) The block header",
        "flowcoin-cli getblockheader \"00000000...\""});

    register_help({"getblockchaininfo", "blockchain",
        "Returns state info regarding blockchain processing.",
        "None",
        "{ chain, blocks, bestblockhash, difficulty, ... }",
        "flowcoin-cli getblockchaininfo"});

    register_help({"gettxout", "blockchain",
        "Returns details about an unspent transaction output.",
        "  txid (string, required) The transaction id\n"
        "  vout (numeric, required) The output index",
        "{ value, pubkey_hash, height, coinbase }",
        "flowcoin-cli gettxout \"txid\" 0"});

    register_help({"verifychain", "blockchain",
        "Verifies blockchain database.",
        "  depth (numeric, optional, default=6) How many blocks to verify",
        "{ valid, checked, depth }",
        "flowcoin-cli verifychain 100"});

    // Mempool
    register_help({"getrawmempool", "blockchain",
        "Returns all transaction ids in memory pool.",
        "  verbose (boolean, optional, default=false)",
        "[ \"txid\", ... ] or { \"txid\": { size, vsize, ... }, ... }",
        "flowcoin-cli getrawmempool true"});

    register_help({"getmempoolinfo", "blockchain",
        "Returns details on the active state of the TX memory pool.",
        "None",
        "{ size, bytes, loaded, mempoolminfee, minrelaytxfee }",
        "flowcoin-cli getmempoolinfo"});

    // Mining
    register_help({"getblocktemplate", "mining",
        "Returns data needed to construct a block to work on.",
        "  coinbase_address (string, optional) Address for coinbase reward",
        "{ height, previousblockhash, nbits, target, ... }",
        "flowcoin-cli getblocktemplate"});

    register_help({"submitblock", "mining",
        "Attempts to submit a new block to the network.",
        "  hex (string, required) The hex-encoded block data",
        "null if accepted, \"reason\" string if rejected",
        "flowcoin-cli submitblock \"hex...\""});

    register_help({"getmininginfo", "mining",
        "Returns mining-related information.",
        "None",
        "{ blocks, difficulty, reward, ... }",
        "flowcoin-cli getmininginfo"});

    // Network
    register_help({"getpeerinfo", "network",
        "Returns data about each connected network node.",
        "None",
        "[ { id, addr, inbound, version, ... }, ... ]",
        "flowcoin-cli getpeerinfo"});

    register_help({"getconnectioncount", "network",
        "Returns the number of connections to other nodes.",
        "None",
        "n (numeric) The connection count",
        "flowcoin-cli getconnectioncount"});

    register_help({"addnode", "network",
        "Attempts to add or remove a node from the addnode list.",
        "  addr (string, required) The node IP:port\n"
        "  command (string, optional) 'add', 'remove', or 'onetry'",
        "true if successful",
        "flowcoin-cli addnode \"192.168.1.1:9555\" add"});

    register_help({"getnetworkinfo", "network",
        "Returns information about the node's network state.",
        "None",
        "{ version, protocolversion, connections, networks, ... }",
        "flowcoin-cli getnetworkinfo"});

    register_help({"getnettotals", "network",
        "Returns information about network traffic.",
        "None",
        "{ totalbytesrecv, totalbytessent, uptime }",
        "flowcoin-cli getnettotals"});

    register_help({"disconnectnode", "network",
        "Disconnects a peer by address.",
        "  addr (string, required) The node IP:port",
        "true if disconnected",
        "flowcoin-cli disconnectnode \"192.168.1.1:9555\""});

    register_help({"listbanned", "network",
        "List all banned IPs/Subnets.",
        "None",
        "[ { address, ban_created, banned_until }, ... ]",
        "flowcoin-cli listbanned"});

    register_help({"setban", "network",
        "Add or remove an IP from the banned list.",
        "  addr (string, required) The IP address\n"
        "  command (string, required) 'add' or 'remove'\n"
        "  duration (numeric, optional) Ban duration in seconds (default 86400)",
        "true",
        "flowcoin-cli setban \"192.168.1.1\" add 3600"});

    register_help({"clearbanned", "network",
        "Clear all banned IPs.",
        "None",
        "true",
        "flowcoin-cli clearbanned"});

    register_help({"ping", "network",
        "Requests that a ping be sent to all other nodes.",
        "None",
        "null",
        "flowcoin-cli ping"});

    // Wallet
    register_help({"getnewaddress", "wallet",
        "Returns a new FlowCoin address for receiving payments.",
        "None",
        "\"address\" (string) The new FlowCoin address",
        "flowcoin-cli getnewaddress"});

    register_help({"getbalance", "wallet",
        "Returns the total available balance.",
        "None",
        "n.nnnnnnnn (numeric) The total balance in FLC",
        "flowcoin-cli getbalance"});

    register_help({"sendtoaddress", "wallet",
        "Send an amount to a given address.",
        "  address (string, required) The FlowCoin address\n"
        "  amount (numeric, required) The amount in FLC",
        "\"txid\" (string) The transaction id",
        "flowcoin-cli sendtoaddress \"fl1q...\" 1.0"});

    register_help({"listunspent", "wallet",
        "Returns array of unspent transaction outputs.",
        "None",
        "[ { txid, vout, amount, ... }, ... ]",
        "flowcoin-cli listunspent"});

    register_help({"listtransactions", "wallet",
        "Returns a list of recent transactions.",
        "  count (numeric, optional, default=10)\n"
        "  skip (numeric, optional, default=0)",
        "[ { txid, amount, timestamp, ... }, ... ]",
        "flowcoin-cli listtransactions 20 0"});

    register_help({"getwalletinfo", "wallet",
        "Returns wallet state info.",
        "None",
        "{ walletname, walletversion, balance, txcount, ... }",
        "flowcoin-cli getwalletinfo"});

    // Utility
    register_help({"help", "util",
        "List all commands, or get help for a specific command.",
        "  command (string, optional) The command to get help on",
        "Help text or method listing",
        "flowcoin-cli help getblockcount"});

    register_help({"stop", "util",
        "Request a graceful shutdown of the node.",
        "None",
        "\"FlowCoin server stopping\"",
        "flowcoin-cli stop"});

    register_help({"uptime", "util",
        "Returns the total uptime of the server in seconds.",
        "None",
        "n (numeric) Seconds since server start",
        "flowcoin-cli uptime"});

    register_help({"getinfo", "util",
        "Returns an object containing various state info.",
        "None",
        "{ version, blocks, connections, balance, ... }",
        "flowcoin-cli getinfo"});

    // Raw transactions
    register_help({"getrawtransaction", "rawtransaction",
        "Return the raw transaction data.",
        "  txid (string, required) The transaction id\n"
        "  verbose (boolean, optional, default=false)",
        "\"hex\" or { txid, version, vin, vout, ... }",
        "flowcoin-cli getrawtransaction \"txid\" true"});

    register_help({"createrawtransaction", "rawtransaction",
        "Create a transaction spending the given inputs.",
        "  inputs (json array, required) [{\"txid\":\"...\",\"vout\":n},...]\n"
        "  outputs (json object, required) {\"address\":amount,...}",
        "\"hex\" (string) The unsigned transaction hex",
        "flowcoin-cli createrawtransaction '[{\"txid\":\"...\",\"vout\":0}]' '{\"fl1q...\":1.0}'"});

    register_help({"sendrawtransaction", "rawtransaction",
        "Submit a raw transaction to the mempool and broadcast.",
        "  hex (string, required) The signed raw transaction hex",
        "\"txid\" (string) The transaction hash",
        "flowcoin-cli sendrawtransaction \"hex...\""});

    register_help({"decoderawtransaction", "rawtransaction",
        "Decode a hex-encoded raw transaction.",
        "  hex (string, required) The transaction hex",
        "{ txid, version, vin, vout, ... }",
        "flowcoin-cli decoderawtransaction \"hex...\""});
}

// ---------------------------------------------------------------------------
// Central registration
// ---------------------------------------------------------------------------

void register_all_rpcs(RpcServer& server, NodeContext& node) {
    // Register help entries first
    register_core_help_entries();

    // Register blockchain RPCs
    if (node.chain) {
        register_blockchain_rpcs(server, *node.chain);
        register_extended_blockchain_rpcs(server, *node.chain);
    }

    // Register mempool RPCs
    if (node.chain && node.mempool) {
        register_mempool_rpcs(server, *node.chain, *node.mempool);
    }

    // Register mining RPCs
    if (node.chain && node.net) {
        register_mining_rpcs(server, *node.chain, *node.net, node.wallet);
    }

    // Register network RPCs
    if (node.net) {
        register_net_rpcs(server, *node.net);
    }

    // Register wallet RPCs
    if (node.wallet && node.chain && node.net) {
        register_wallet_rpcs(server, *node.wallet, *node.chain, *node.net);
    }

    // Register raw transaction RPCs
    if (node.chain && node.mempool && node.wallet && node.net) {
        register_rawtx_rpcs(server, *node.chain, *node.mempool,
                            *node.wallet, *node.net);
    }

    // Register utility RPCs
    if (node.chain && node.wallet && node.net && node.mempool) {
        register_util_rpcs(server, *node.chain, *node.wallet,
                          *node.net, *node.mempool);
    }

    // Register debug RPCs
    if (node.chain && node.mempool && node.wallet) {
        register_debug_rpcs(server, *node.chain, *node.mempool, *node.wallet);
    }

    // Register the enhanced help method using the help system
    server.register_method("help2", [](const json& params) -> json {
        if (!params.empty() && params[0].is_string()) {
            std::string name = params[0].get<std::string>();
            RpcMethodHelp help;
            if (get_method_help(name, help)) {
                return format_help(help);
            }
            return "Unknown method: " + name;
        }
        return format_help_all();
    });

    // Register method listing
    server.register_method("listmethods", [](const json& params) -> json {
        if (!params.empty() && params[0].is_string()) {
            std::string category = params[0].get<std::string>();
            auto entries = get_category_help(category);
            json result = json::array();
            for (const auto& entry : entries) {
                json j;
                j["name"] = entry.name;
                j["summary"] = entry.summary;
                result.push_back(j);
            }
            return result;
        }

        auto categories = list_methods_by_category();
        json result = json::object();
        for (const auto& [cat, methods] : categories) {
            json arr = json::array();
            for (const auto& m : methods) {
                arr.push_back(m);
            }
            result[cat] = arr;
        }
        return result;
    });
}

} // namespace flow
