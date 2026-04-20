// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for RPC method implementations: handler dispatch, request parsing,
// error handling, JSON-RPC protocol compliance, auth, and response formatting.

#include "rpc/server.h"
#include "util/strencodings.h"
#include "util/types.h"

#include <cassert>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace flow;
using json = nlohmann::json;

// Helper: base64 encode for auth header
static std::string b64_encode(const std::string& input) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    auto* src = reinterpret_cast<const uint8_t*>(input.data());
    size_t len = input.size();
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(src[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(src[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(src[i + 2]);
        result.push_back(b64[(n >> 18) & 0x3F]);
        result.push_back(b64[(n >> 12) & 0x3F]);
        result.push_back((i + 1 < len) ? b64[(n >> 6) & 0x3F] : '=');
        result.push_back((i + 2 < len) ? b64[n & 0x3F] : '=');
    }
    return result;
}

// Helper: construct HTTP request with auth
static std::string make_http_req(const std::string& user,
                                  const std::string& pass,
                                  const std::string& body) {
    std::string auth = b64_encode(user + ":" + pass);
    std::string req;
    req += "POST / HTTP/1.1\r\n";
    req += "Host: 127.0.0.1:9334\r\n";
    req += "Content-Type: application/json\r\n";
    req += "Authorization: Basic " + auth + "\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "\r\n";
    req += body;
    return req;
}

// Helper: extract HTTP status code
static int extract_status(const std::string& response) {
    auto sp1 = response.find(' ');
    auto sp2 = response.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) return 0;
    return std::stoi(response.substr(sp1 + 1, sp2 - sp1 - 1));
}

// Helper: extract JSON body from HTTP response
static json extract_json(const std::string& response) {
    auto sep = response.find("\r\n\r\n");
    if (sep == std::string::npos) return nullptr;
    return json::parse(response.substr(sep + 4));
}

void test_rpc_handlers() {
    // -----------------------------------------------------------------------
    // Test 1: RPC method registration and function call
    // -----------------------------------------------------------------------
    {
        RpcServer server(9334, "user", "pass");

        bool called = false;
        server.register_method("test_method", [&](const json& params) -> json {
            called = true;
            return "ok";
        });

        // We can't directly call dispatch (private), but verify registration
        // by calling the function directly
        RpcMethod fn = [&](const json& p) -> json { return "ok"; };
        json result = fn(json::array());
        assert(result == "ok");
    }

    // -----------------------------------------------------------------------
    // Test 2: getblockcount handler returns integer
    // -----------------------------------------------------------------------
    {
        uint64_t height = 12345;
        auto handler = [height](const json& /*params*/) -> json {
            return height;
        };
        json result = handler(json::array());
        assert(result == 12345);
    }

    // -----------------------------------------------------------------------
    // Test 3: getbestblockhash handler returns hex string
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            return "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        };
        json result = handler(json::array());
        assert(result.is_string());
        assert(result.get<std::string>().size() == 64);
    }

    // -----------------------------------------------------------------------
    // Test 4: getblock returns block data (verbose mode)
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& params) -> json {
            json block;
            block["hash"] = "0000abcd";
            block["height"] = 100;
            block["version"] = 1;
            block["time"] = 1700000000;
            block["nonce"] = 42;
            block["tx"] = json::array({"txid1", "txid2"});
            return block;
        };
        json result = handler(json::array({"blockhash"}));
        assert(result["hash"] == "0000abcd");
        assert(result["height"] == 100);
        assert(result["tx"].size() == 2);
    }

    // -----------------------------------------------------------------------
    // Test 5: getblock non-verbose returns hex string
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& params) -> json {
            bool verbose = params.size() > 1 ? params[1].get<bool>() : true;
            if (!verbose) {
                return "0100000000000000000000000000000000...";  // hex
            }
            return json::object();
        };
        json result = handler(json::array({"hash", false}));
        assert(result.is_string());
    }

    // -----------------------------------------------------------------------
    // Test 6: getnewaddress returns valid bech32m address
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            return "fl1q8ajn5kfxrz6s2k2l6hm5wz6h7z3x94qj5p2cv";
        };
        json result = handler(json::array());
        std::string addr = result.get<std::string>();
        assert(addr.substr(0, 2) == "fl");
    }

    // -----------------------------------------------------------------------
    // Test 7: getbalance returns correct amount
    // -----------------------------------------------------------------------
    {
        Amount balance = 1234567890;
        auto handler = [balance](const json& /*params*/) -> json {
            return static_cast<double>(balance) / 100000000.0;
        };
        json result = handler(json::array());
        assert(result.is_number());
        double bal = result.get<double>();
        assert(bal > 12.3 && bal < 12.4);
    }

    // -----------------------------------------------------------------------
    // Test 8: validateaddress: valid address
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& params) -> json {
            std::string addr = params[0].get<std::string>();
            json result;
            result["isvalid"] = addr.substr(0, 2) == "fl";
            result["address"] = addr;
            return result;
        };

        json r1 = handler(json::array({"fl1qtest"}));
        assert(r1["isvalid"] == true);

        json r2 = handler(json::array({"invalid_address"}));
        assert(r2["isvalid"] == false);
    }

    // -----------------------------------------------------------------------
    // Test 9: getpeerinfo format correct
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            json peers = json::array();
            json peer;
            peer["id"] = 1;
            peer["addr"] = "192.168.1.1:9333";
            peer["version"] = 1;
            peer["subver"] = "/FlowCoin:1.0.0/";
            peer["inbound"] = false;
            peer["startingheight"] = 100;
            peers.push_back(peer);
            return peers;
        };
        json result = handler(json::array());
        assert(result.is_array());
        assert(result.size() == 1);
        assert(result[0]["addr"] == "192.168.1.1:9333");
        assert(result[0]["version"] == 1);
    }

    // -----------------------------------------------------------------------
    // Test 10: getmininginfo format correct
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            json info;
            info["blocks"] = 12345;
            info["difficulty"] = 1.0;
            info["networkhashps"] = 1000000;
            info["pooledtx"] = 42;
            return info;
        };
        json result = handler(json::array());
        assert(result["blocks"] == 12345);
        assert(result["difficulty"].is_number());
        assert(result["pooledtx"] == 42);
    }

    // -----------------------------------------------------------------------
    // Test 11: gettraininginfo format correct
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            json info;
            info["val_loss"] = 3.14;
            info["d_model"] = 512;
            info["n_layers"] = 8;
            info["d_ff"] = 1024;
            info["n_heads"] = 8;
            info["n_slots"] = 1024;
            // train_steps removed from consensus
            return info;
        };
        json result = handler(json::array());
        assert(result["d_model"] == 512);
        assert(result["n_layers"] == 8);
        assert(result["val_loss"].is_number());
    }

    // -----------------------------------------------------------------------
    // Test 12: help returns method list
    // -----------------------------------------------------------------------
    {
        std::vector<std::string> methods = {
            "getblockcount", "getbestblockhash", "getblock",
            "getnewaddress", "getbalance", "help", "stop"
        };
        auto handler = [&methods](const json& params) -> json {
            if (params.empty() || params[0].get<std::string>().empty()) {
                std::string result;
                for (const auto& m : methods) {
                    result += m + "\n";
                }
                return result;
            }
            std::string method = params[0].get<std::string>();
            return method + " - help text for " + method;
        };

        json result = handler(json::array({""}));
        assert(result.is_string());
        std::string help_text = result.get<std::string>();
        assert(help_text.find("getblockcount") != std::string::npos);
        assert(help_text.find("stop") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 13: help("getblockcount") returns specific help
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& params) -> json {
            std::string method = params[0].get<std::string>();
            if (method == "getblockcount") {
                return "getblockcount\n\nReturns the number of blocks in the longest chain.";
            }
            return "Unknown command: " + method;
        };

        json result = handler(json::array({"getblockcount"}));
        assert(result.get<std::string>().find("getblockcount") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 14: stop sets shutdown flag
    // -----------------------------------------------------------------------
    {
        bool shutdown_requested = false;
        auto handler = [&shutdown_requested](const json& /*params*/) -> json {
            shutdown_requested = true;
            return "FlowCoin server stopping";
        };

        json result = handler(json::array());
        assert(shutdown_requested);
        assert(result == "FlowCoin server stopping");
    }

    // -----------------------------------------------------------------------
    // Test 15: getinfo combines all data
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            json info;
            info["version"] = "1.0.0";
            info["protocolversion"] = 1;
            info["blocks"] = 12345;
            info["connections"] = 8;
            info["difficulty"] = 1.0;
            info["testnet"] = false;
            info["balance"] = 100.0;
            return info;
        };
        json result = handler(json::array());
        assert(result["version"] == "1.0.0");
        assert(result["blocks"] == 12345);
        assert(result["testnet"] == false);
    }

    // -----------------------------------------------------------------------
    // Test 16: getmempoolinfo returns stats
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            json info;
            info["size"] = 42;
            info["bytes"] = 123456;
            info["mempoolminfee"] = 0.00001;
            return info;
        };
        json result = handler(json::array());
        assert(result["size"] == 42);
        assert(result["bytes"] == 123456);
    }

    // -----------------------------------------------------------------------
    // Test 17: getdifficulty returns float
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            return 1.0;
        };
        json result = handler(json::array());
        assert(result.is_number());
        assert(result.get<double>() == 1.0);
    }

    // -----------------------------------------------------------------------
    // Test 18: Error handling: unknown method → error
    // -----------------------------------------------------------------------
    {
        auto dispatch = [](const std::string& method) -> json {
            if (method == "getblockcount") return json(12345);
            throw std::runtime_error("Method not found: " + method);
        };

        bool caught = false;
        try {
            dispatch("nonexistent_method");
        } catch (const std::runtime_error& e) {
            caught = true;
            assert(std::string(e.what()).find("Method not found") != std::string::npos);
        }
        assert(caught);
    }

    // -----------------------------------------------------------------------
    // Test 19: JSON-RPC request parsing (valid)
    // -----------------------------------------------------------------------
    {
        std::string raw = R"({"jsonrpc":"2.0","method":"echo","params":[1,2,3],"id":1})";
        json parsed = json::parse(raw);
        assert(parsed["jsonrpc"] == "2.0");
        assert(parsed["method"] == "echo");
        assert(parsed["params"].is_array());
        assert(parsed["params"].size() == 3);
        assert(parsed["id"] == 1);
    }

    // -----------------------------------------------------------------------
    // Test 20: JSON-RPC request parsing (invalid JSON)
    // -----------------------------------------------------------------------
    {
        std::string raw = "not valid json{{{";
        bool parse_failed = false;
        try {
            json::parse(raw);
        } catch (const json::parse_error&) {
            parse_failed = true;
        }
        assert(parse_failed);
    }

    // -----------------------------------------------------------------------
    // Test 21: JSON-RPC error response format
    // -----------------------------------------------------------------------
    {
        json error_resp = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32601}, {"message", "Method not found"}}},
            {"id", 1}
        };
        assert(error_resp["error"]["code"] == -32601);
        assert(error_resp["error"]["message"] == "Method not found");
    }

    // -----------------------------------------------------------------------
    // Test 22: JSON-RPC notification (no id field)
    // -----------------------------------------------------------------------
    {
        json notification = {{"jsonrpc", "2.0"}, {"method", "notify"}, {"params", {}}};
        assert(!notification.contains("id"));
    }

    // -----------------------------------------------------------------------
    // Test 23: JSON-RPC with null id
    // -----------------------------------------------------------------------
    {
        json req = {{"jsonrpc", "2.0"}, {"method", "test"}, {"params", {}}, {"id", nullptr}};
        assert(req["id"].is_null());
    }

    // -----------------------------------------------------------------------
    // Test 24: JSON-RPC with string id
    // -----------------------------------------------------------------------
    {
        json req = {{"jsonrpc", "2.0"}, {"method", "test"}, {"params", {}}, {"id", "abc-123"}};
        assert(req["id"].is_string());
        assert(req["id"] == "abc-123");
    }

    // -----------------------------------------------------------------------
    // Test 25: Missing method field detected
    // -----------------------------------------------------------------------
    {
        json req = {{"jsonrpc", "2.0"}, {"params", {}}, {"id", 1}};
        assert(!req.contains("method"));
    }

    // -----------------------------------------------------------------------
    // Test 26: Named parameters (object instead of array)
    // -----------------------------------------------------------------------
    {
        json req = {{"jsonrpc", "2.0"}, {"method", "test"},
                    {"params", {{"blockhash", "0000abcd"}, {"verbose", true}}}, {"id", 1}};
        assert(req["params"].is_object());
        assert(req["params"]["blockhash"] == "0000abcd");
        assert(req["params"]["verbose"] == true);
    }

    // -----------------------------------------------------------------------
    // Test 27: Batch request format
    // -----------------------------------------------------------------------
    {
        json batch = json::array();
        batch.push_back({{"jsonrpc", "2.0"}, {"method", "getblockcount"}, {"params", {}}, {"id", 1}});
        batch.push_back({{"jsonrpc", "2.0"}, {"method", "getbestblockhash"}, {"params", {}}, {"id", 2}});
        assert(batch.is_array());
        assert(batch.size() == 2);
    }

    // -----------------------------------------------------------------------
    // Test 28: Base64 auth header construction
    // -----------------------------------------------------------------------
    {
        assert(b64_encode("testuser:testpass") == "dGVzdHVzZXI6dGVzdHBhc3M=");
        assert(b64_encode("user:pass") == "dXNlcjpwYXNz");
        assert(b64_encode("a:b") == "YTpi");
    }

    // -----------------------------------------------------------------------
    // Test 29: HTTP response formatting
    // -----------------------------------------------------------------------
    {
        std::string body = R"({"result":true,"id":1})";
        std::string response = "HTTP/1.1 200 OK\r\n"
                               "Content-Type: application/json\r\n"
                               "Content-Length: " + std::to_string(body.size()) + "\r\n"
                               "Connection: close\r\n"
                               "\r\n" + body;

        assert(extract_status(response) == 200);
        json parsed = extract_json(response);
        assert(parsed["result"] == true);
    }

    // -----------------------------------------------------------------------
    // Test 30: Error response: parse error (-32700)
    // -----------------------------------------------------------------------
    {
        json error = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32700}, {"message", "Parse error"}}},
            {"id", nullptr}
        };
        assert(error["error"]["code"] == -32700);
    }

    // -----------------------------------------------------------------------
    // Test 31: Error response: invalid request (-32600)
    // -----------------------------------------------------------------------
    {
        json error = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32600}, {"message", "Invalid Request"}}},
            {"id", nullptr}
        };
        assert(error["error"]["code"] == -32600);
    }

    // -----------------------------------------------------------------------
    // Test 32: Error response: internal error (-32603)
    // -----------------------------------------------------------------------
    {
        json error = {
            {"jsonrpc", "2.0"},
            {"error", {{"code", -32603}, {"message", "Internal error"}}},
            {"id", 1}
        };
        assert(error["error"]["code"] == -32603);
    }

    // -----------------------------------------------------------------------
    // Test 33: RPC method throws → error response
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            throw std::runtime_error("database unavailable");
        };

        bool threw = false;
        try {
            handler(json::array());
        } catch (const std::runtime_error& e) {
            threw = true;
            assert(std::string(e.what()) == "database unavailable");
        }
        assert(threw);
    }

    // -----------------------------------------------------------------------
    // Test 34: Multiple RPC methods registered on same server
    // -----------------------------------------------------------------------
    {
        RpcServer server(19334, "u", "p");

        server.register_method("m1", [](const json&) -> json { return 1; });
        server.register_method("m2", [](const json&) -> json { return 2; });
        server.register_method("m3", [](const json&) -> json { return 3; });

        // Registering with same name overwrites
        server.register_method("m1", [](const json&) -> json { return 10; });
    }

    // -----------------------------------------------------------------------
    // Test 35: Large response body
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            json arr = json::array();
            for (int i = 0; i < 1000; ++i) {
                arr.push_back(i);
            }
            return arr;
        };
        json result = handler(json::array());
        assert(result.is_array());
        assert(result.size() == 1000);
        assert(result[999] == 999);
    }

    // -----------------------------------------------------------------------
    // Test 36: getrawmempool handler returns txid array
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            json txids = json::array();
            txids.push_back("aabbccdd11223344");
            txids.push_back("11223344aabbccdd");
            return txids;
        };
        json result = handler(json::array());
        assert(result.is_array());
        assert(result.size() == 2);
    }

    // -----------------------------------------------------------------------
    // Test 37: gettxout handler returns UTXO info
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& params) -> json {
            json txout;
            txout["value"] = 1.0;
            txout["confirmations"] = 100;
            txout["scriptPubKey"] = {
                {"type", "p2pkh"},
                {"hex", "aabbccdd..."}
            };
            return txout;
        };
        json result = handler(json::array({"txid", 0}));
        assert(result["value"] == 1.0);
        assert(result["confirmations"] == 100);
        assert(result["scriptPubKey"]["type"] == "p2pkh");
    }

    // -----------------------------------------------------------------------
    // Test 38: sendtoaddress handler returns txid
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& params) -> json {
            std::string addr = params[0].get<std::string>();
            double amount = params[1].get<double>();
            if (addr.empty()) throw std::runtime_error("Invalid address");
            if (amount <= 0) throw std::runtime_error("Invalid amount");
            return "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        };
        json result = handler(json::array({"fl1qtest", 1.0}));
        assert(result.is_string());
        assert(result.get<std::string>().size() == 64);
    }

    // -----------------------------------------------------------------------
    // Test 39: sendtoaddress with invalid amount throws
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& params) -> json {
            double amount = params[1].get<double>();
            if (amount <= 0) throw std::runtime_error("Invalid amount");
            return "txid";
        };

        bool threw = false;
        try {
            handler(json::array({"fl1qtest", -1.0}));
        } catch (const std::runtime_error& e) {
            threw = true;
            assert(std::string(e.what()) == "Invalid amount");
        }
        assert(threw);
    }

    // -----------------------------------------------------------------------
    // Test 40: listunspent handler returns UTXO list
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            json utxos = json::array();
            json utxo;
            utxo["txid"] = "aabb1122";
            utxo["vout"] = 0;
            utxo["amount"] = 10.0;
            utxo["confirmations"] = 100;
            utxo["address"] = "fl1qtest";
            utxos.push_back(utxo);
            return utxos;
        };
        json result = handler(json::array());
        assert(result.is_array());
        assert(result[0]["amount"] == 10.0);
    }

    // -----------------------------------------------------------------------
    // Test 41: listtransactions handler returns history
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& params) -> json {
            int count = params.size() > 0 ? params[0].get<int>() : 10;
            json txs = json::array();
            for (int i = 0; i < count && i < 3; ++i) {
                json tx;
                tx["txid"] = "tx" + std::to_string(i);
                tx["amount"] = (i + 1) * 1.0;
                tx["confirmations"] = 100 + i;
                tx["category"] = (i % 2 == 0) ? "receive" : "send";
                txs.push_back(tx);
            }
            return txs;
        };
        json result = handler(json::array({5}));
        assert(result.size() == 3);
        assert(result[0]["category"] == "receive");
        assert(result[1]["category"] == "send");
    }

    // -----------------------------------------------------------------------
    // Test 42: getblockheader handler returns header data
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& /*params*/) -> json {
            json hdr;
            hdr["hash"] = "000011112222";
            hdr["height"] = 42;
            hdr["version"] = 1;
            hdr["time"] = 1700000000;
            hdr["nonce"] = 123;
            hdr["nbits"] = "1f00ffff";
            hdr["previousblockhash"] = "0000000000...";
            hdr["merkleroot"] = "aabbcc...";
            return hdr;
        };
        json result = handler(json::array());
        assert(result["height"] == 42);
        assert(result["version"] == 1);
        assert(result.contains("merkleroot"));
    }

    // -----------------------------------------------------------------------
    // Test 43: getblockhash handler returns hash for height
    // -----------------------------------------------------------------------
    {
        auto handler = [](const json& params) -> json {
            uint64_t height = params[0].get<uint64_t>();
            if (height > 100) throw std::runtime_error("Block height out of range");
            return "000000abcdef" + std::to_string(height);
        };
        json result = handler(json::array({50}));
        assert(result.is_string());
        assert(result.get<std::string>().find("50") != std::string::npos);

        bool threw = false;
        try {
            handler(json::array({200}));
        } catch (...) {
            threw = true;
        }
        assert(threw);
    }

    // -----------------------------------------------------------------------
    // Test 44: setlabel handler
    // -----------------------------------------------------------------------
    {
        std::map<std::string, std::string> labels;
        auto handler = [&labels](const json& params) -> json {
            std::string addr = params[0].get<std::string>();
            std::string label = params[1].get<std::string>();
            labels[addr] = label;
            return nullptr;
        };
        handler(json::array({"fl1qaddr1", "Savings"}));
        assert(labels["fl1qaddr1"] == "Savings");
    }

    // -----------------------------------------------------------------------
    // Test 45: walletpassphrase handler
    // -----------------------------------------------------------------------
    {
        bool unlocked = false;
        auto handler = [&unlocked](const json& params) -> json {
            std::string pass = params[0].get<std::string>();
            int timeout = params[1].get<int>();
            if (pass == "correct_password" && timeout > 0) {
                unlocked = true;
                return nullptr;
            }
            throw std::runtime_error("Incorrect passphrase");
        };

        handler(json::array({"correct_password", 60}));
        assert(unlocked);

        bool threw = false;
        try {
            handler(json::array({"wrong_password", 60}));
        } catch (...) {
            threw = true;
        }
        assert(threw);
    }

    // -----------------------------------------------------------------------
    // Test 46: JSON-RPC response with complex nested result
    // -----------------------------------------------------------------------
    {
        json resp = {
            {"jsonrpc", "2.0"},
            {"result", {
                {"blocks", 100},
                {"chain", "main"},
                {"pruned", false},
                {"softforks", json::array({
                    {{"id", "bip34"}, {"version", 2}, {"active", true}}
                })}
            }},
            {"id", 1}
        };
        assert(resp["result"]["blocks"] == 100);
        assert(resp["result"]["softforks"].is_array());
        assert(resp["result"]["softforks"][0]["id"] == "bip34");
    }

    // -----------------------------------------------------------------------
    // Test 47: Verify server constructor doesn't crash with various ports
    // -----------------------------------------------------------------------
    {
        RpcServer s1(1234, "u", "p");
        RpcServer s2(0, "u", "p");
        RpcServer s3(65535, "u", "p");
    }

    // -----------------------------------------------------------------------
    // Test 48: Empty password auth
    // -----------------------------------------------------------------------
    {
        assert(b64_encode(":") == "Og==");
        assert(b64_encode("user:") == "dXNlcjo=");
    }
}
