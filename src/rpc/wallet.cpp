// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "rpc/wallet.h"
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "wallet/walletutil.h"
#include "chain/chainstate.h"
#include "chain/utxo.h"
#include "net/net.h"
#include "consensus/params.h"
#include "crypto/bech32.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "util/strencodings.h"

#include <cstring>
#include <stdexcept>

namespace flow {

void register_wallet_rpcs(RpcServer& server, Wallet& wallet,
                          ChainState& chain, NetManager& net) {

    // getnewaddress: generate a new receiving address
    server.register_method("getnewaddress", [&wallet](const json& /*params*/) -> json {
        std::string addr = wallet.get_new_address();
        if (addr.empty()) {
            throw std::runtime_error("Failed to generate new address");
        }
        return addr;
    });

    // getbalance: return wallet balance in FLC
    server.register_method("getbalance", [&wallet](const json& /*params*/) -> json {
        Amount balance = wallet.get_balance();
        return static_cast<double>(balance) / static_cast<double>(consensus::COIN);
    });

    // listunspent: list wallet UTXOs
    server.register_method("listunspent", [&wallet, &chain](const json& /*params*/) -> json {
        json result = json::array();

        auto coins = wallet.list_unspent();
        uint64_t tip_height = chain.height();

        for (const auto& coin : coins) {
            json u;
            u["txid"]   = hex_encode(coin.txid.data(), 32);
            u["vout"]   = coin.vout;
            u["amount"] = static_cast<double>(coin.value) /
                          static_cast<double>(consensus::COIN);

            // address: bech32m-encoded from pubkey
            u["address"] = pubkey_to_address(coin.pubkey.data());

            // scriptPubKey: OP_0 <20-byte-pubkey-hash> as hex
            // The witness program is the keccak256d hash of the pubkey (first 20 bytes)
            {
                std::string addr = pubkey_to_address(coin.pubkey.data());
                std::vector<uint8_t> pkh;
                if (address_to_pubkey_hash(addr, pkh) && pkh.size() == 20) {
                    // OP_0 (0x00) + push 20 bytes (0x14) + 20-byte hash
                    std::vector<uint8_t> script;
                    script.push_back(0x00);
                    script.push_back(0x14);
                    script.insert(script.end(), pkh.begin(), pkh.end());
                    u["scriptPubKey"] = hex_encode(script);
                } else {
                    u["scriptPubKey"] = "";
                }
            }

            u["solvable"]  = true;
            u["safe"]      = true;

            // FlowCoin-specific bonus fields
            u["pubkey"] = hex_encode(coin.pubkey.data(), 32);

            // Look up the UTXO entry for height and coinbase info
            UTXOEntry entry;
            if (chain.utxo_set().get(coin.txid, coin.vout, entry)) {
                u["height"]   = entry.height;
                u["coinbase"] = entry.is_coinbase;

                u["confirmations"] = (entry.height <= tip_height)
                    ? static_cast<int64_t>(tip_height - entry.height + 1) : 0;

                bool spendable = true;
                if (entry.is_coinbase) {
                    spendable = (tip_height >= entry.height + consensus::COINBASE_MATURITY);
                }
                u["spendable"] = spendable;
            } else {
                u["height"]        = 0;
                u["coinbase"]      = false;
                u["confirmations"] = 0;
                u["spendable"]     = true;
            }

            result.push_back(u);
        }

        return result;
    });

    // sendtoaddress(addr, amount): send coins
    server.register_method("sendtoaddress", [&wallet, &net](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("Usage: sendtoaddress <address> <amount>");
        }
        std::string dest_addr = params[0].get<std::string>();
        double amount_flow = params[1].get<double>();

        if (amount_flow <= 0.0) {
            throw std::runtime_error("Amount must be positive");
        }

        Amount amount_atomic = static_cast<Amount>(amount_flow * consensus::COIN + 0.5);

        auto result = wallet.send_to_address(dest_addr, amount_atomic);
        if (!result.success) {
            throw std::runtime_error(result.error);
        }

        uint256 txid = result.tx.get_txid();

        // Broadcast via P2P
        net.broadcast_transaction(result.tx);

        return hex_encode(txid.data(), 32);
    });

    // listtransactions(count, skip): transaction history
    server.register_method("listtransactions", [&wallet, &chain](const json& params) -> json {
        int count = 10;
        int skip = 0;
        if (params.size() > 0 && params[0].is_number_integer()) {
            count = params[0].get<int>();
        }
        if (params.size() > 1 && params[1].is_number_integer()) {
            skip = params[1].get<int>();
        }

        auto txs = wallet.get_transactions(count, skip);
        uint64_t tip_height = chain.height();
        json result = json::array();
        for (const auto& wtx : txs) {
            json j;
            j["txid"]      = hex_encode(wtx.txid.data(), 32);
            j["amount"]    = static_cast<double>(wtx.amount) /
                             static_cast<double>(consensus::COIN);
            j["time"]      = wtx.timestamp;
            j["address"]   = wtx.address;

            // category: "generate" for coinbase, "receive" for incoming, "send" for outgoing
            if (wtx.is_coinbase)
                j["category"] = "generate";
            else if (wtx.is_send)
                j["category"] = "send";
            else
                j["category"] = "receive";

            // confirmations
            if (wtx.block_height > 0 && wtx.block_height <= tip_height) {
                j["confirmations"] = static_cast<int64_t>(tip_height - wtx.block_height + 1);
            } else {
                j["confirmations"] = 0;
            }

            j["blockhash"]   = hex_encode(wtx.block_hash.data(), 32);
            j["blockheight"] = wtx.block_height;
            j["blocktime"]   = wtx.timestamp;  // best approximation available
            j["label"]       = wtx.label;
            result.push_back(j);
        }
        return result;
    });

    // validateaddress(addr): check if an address is valid Bech32m
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
            j["hrp"]             = decoded.hrp;
            j["witness_version"] = decoded.witness_version;
            j["witness_program"] = hex_encode(decoded.program.data(),
                                              decoded.program.size());
            j["isscript"]  = false;
            j["iswitness"] = true;

            // scriptPubKey: OP_0 <20-byte-witness-program>
            if (decoded.program.size() == 20) {
                std::vector<uint8_t> script;
                script.push_back(0x00);
                script.push_back(0x14);
                script.insert(script.end(), decoded.program.begin(),
                              decoded.program.end());
                j["scriptPubKey"] = hex_encode(script);
            } else {
                j["scriptPubKey"] = hex_encode(decoded.program.data(),
                                               decoded.program.size());
            }

            bool is_mainnet = (decoded.hrp == consensus::MAINNET_HRP);
            bool is_testnet = (decoded.hrp == consensus::TESTNET_HRP);
            bool is_regtest = (decoded.hrp == consensus::REGTEST_HRP);
            // FlowCoin-specific bonus fields
            j["network"] = is_mainnet ? "mainnet" :
                           is_testnet ? "testnet" :
                           is_regtest ? "regtest" : "unknown";
        }
        return j;
    });

    // -----------------------------------------------------------------------
    // importprivkey(hex): import a raw Ed25519 private key (32-byte seed)
    // -----------------------------------------------------------------------
    server.register_method("importprivkey", [&wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: importprivkey <hex_privkey>");
        }
        std::string hex_key = params[0].get<std::string>();
        auto bytes = hex_decode(hex_key);
        if (bytes.size() != 32) {
            throw std::runtime_error("Private key must be exactly 32 bytes (64 hex chars)");
        }

        std::array<uint8_t, 32> privkey;
        std::memcpy(privkey.data(), bytes.data(), 32);

        if (!wallet.import_privkey(privkey)) {
            throw std::runtime_error("Failed to import private key");
        }

        // Derive the address for the response
        auto pubkey = derive_pubkey(privkey.data());
        std::string addr = pubkey_to_address(pubkey.data());

        json j;
        j["address"] = addr;
        j["pubkey"]  = hex_encode(pubkey.data(), 32);
        j["imported"] = true;
        return j;
    });

    // -----------------------------------------------------------------------
    // dumpprivkey(address): export the private key for a wallet address
    // Note: this requires access to wallet internals. The wallet must expose
    // a method to retrieve private keys by address. For now, we return an
    // error indicating the wallet must be unlocked or the key is not found.
    // -----------------------------------------------------------------------
    server.register_method("dumpprivkey", [&wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: dumpprivkey <address>");
        }
        std::string addr = params[0].get<std::string>();

        if (!wallet.is_mine(addr)) {
            throw std::runtime_error("Address not found in wallet");
        }

        // The wallet does not currently expose a public API for exporting
        // private keys by address. This RPC returns the address info and
        // confirms ownership. Full private key export requires the
        // wallet.get_privkey_for_address() method.
        throw std::runtime_error("Wallet does not support direct private key export via RPC. "
                                  "Use dumpwallet to create a full backup.");
    });

    // -----------------------------------------------------------------------
    // dumpwallet(path): dump all wallet addresses to a file
    // -----------------------------------------------------------------------
    server.register_method("dumpwallet", [&wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: dumpwallet <filepath>");
        }
        std::string path = params[0].get<std::string>();

        if (!walletutil::dump_wallet(wallet, path)) {
            throw std::runtime_error("Failed to dump wallet to " + path);
        }

        json j;
        j["filename"] = path;
        return j;
    });

    // -----------------------------------------------------------------------
    // importwallet(path): import keys from a dump file
    // -----------------------------------------------------------------------
    server.register_method("importwallet", [&wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: importwallet <filepath>");
        }
        std::string path = params[0].get<std::string>();

        if (!walletutil::import_wallet(wallet, path)) {
            throw std::runtime_error("Failed to import wallet from " + path
                                      + " (no valid KEY entries found)");
        }

        json j;
        j["filename"] = path;
        j["imported"]  = true;
        return j;
    });

    // -----------------------------------------------------------------------
    // backupwallet(path): copy wallet.dat to a destination
    // -----------------------------------------------------------------------
    server.register_method("backupwallet", [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: backupwallet <destination_path>");
        }
        std::string dest = params[0].get<std::string>();

        std::string wallet_path = walletutil::get_wallet_path(chain.datadir());
        if (!walletutil::backup_wallet(wallet_path, dest)) {
            throw std::runtime_error("Failed to backup wallet to " + dest);
        }

        json j;
        j["source"]      = wallet_path;
        j["destination"]  = dest;
        return j;
    });

    // -----------------------------------------------------------------------
    // encryptwallet(passphrase): encrypt the wallet
    // -----------------------------------------------------------------------
    server.register_method("encryptwallet", [&wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: encryptwallet <passphrase>");
        }
        std::string passphrase = params[0].get<std::string>();
        if (passphrase.empty()) {
            throw std::runtime_error("Passphrase must not be empty");
        }

        if (wallet.is_encrypted()) {
            throw std::runtime_error("Wallet is already encrypted");
        }

        if (!wallet.encrypt_wallet(passphrase)) {
            throw std::runtime_error("Failed to encrypt wallet");
        }

        json j;
        j["encrypted"] = true;
        j["warning"] = "Wallet encrypted successfully. The node will need "
                        "to be restarted. Remember to unlock the wallet with "
                        "walletpassphrase before sending transactions.";
        return j;
    });

    // -----------------------------------------------------------------------
    // walletpassphrase(passphrase, timeout): unlock wallet
    // -----------------------------------------------------------------------
    server.register_method("walletpassphrase", [&wallet](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("Usage: walletpassphrase <passphrase> <timeout>");
        }
        std::string passphrase = params[0].get<std::string>();
        int timeout = params[1].get<int>();

        if (!wallet.is_encrypted()) {
            throw std::runtime_error("Wallet is not encrypted");
        }

        if (!wallet.walletpassphrase(passphrase, timeout)) {
            throw std::runtime_error("Incorrect passphrase or wallet error");
        }

        json j;
        j["unlocked"] = true;
        j["timeout"] = timeout;
        return j;
    });

    // -----------------------------------------------------------------------
    // walletlock: lock the wallet
    // -----------------------------------------------------------------------
    server.register_method("walletlock", [&wallet](const json& /*params*/) -> json {
        wallet.walletlock();
        json j;
        j["locked"] = true;
        return j;
    });

    // -----------------------------------------------------------------------
    // signmessage(address, message): sign a message with the private key
    // associated with a wallet address
    // -----------------------------------------------------------------------
    server.register_method("signmessage", [&wallet](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("Usage: signmessage <address> <message>");
        }
        std::string addr = params[0].get<std::string>();
        std::string message = params[1].get<std::string>();

        if (!wallet.is_mine(addr)) {
            throw std::runtime_error("Address not found in wallet");
        }

        auto sig_data = wallet.sign_message(addr, message);
        return hex_encode(sig_data);
    });

    // -----------------------------------------------------------------------
    // verifymessage(address, signature_hex, message): verify a signed message
    // -----------------------------------------------------------------------
    server.register_method("verifymessage", [](const json& params) -> json {
        if (params.size() < 3) {
            throw std::runtime_error("Usage: verifymessage <address> <signature_hex> <message>");
        }
        std::string addr     = params[0].get<std::string>();
        std::string sig_hex  = params[1].get<std::string>();
        std::string message  = params[2].get<std::string>();

        // Decode the address to extract the pubkey hash
        auto decoded = bech32m_decode(addr);
        if (!decoded.valid || decoded.program.size() != 20) {
            throw std::runtime_error("Invalid address");
        }

        // Decode the signature
        auto sig_bytes = hex_decode(sig_hex);
        if (sig_bytes.size() != 96) {
            // Expect 64-byte signature + 32-byte pubkey = 96 bytes
            throw std::runtime_error("Signature must be 96 bytes hex "
                                      "(64-byte Ed25519 sig + 32-byte pubkey)");
        }

        std::array<uint8_t, 64> signature;
        std::array<uint8_t, 32> pubkey;
        std::memcpy(signature.data(), sig_bytes.data(), 64);
        std::memcpy(pubkey.data(), sig_bytes.data() + 64, 32);

        // Verify the pubkey matches the address
        std::string derived_addr = pubkey_to_address(pubkey.data());
        if (derived_addr != addr) {
            json j;
            j["valid"]   = false;
            j["error"]   = "Public key does not match address";
            return j;
        }

        // Reconstruct the signed message preimage
        std::string preimage = "FlowCoin Signed Message:\n" + message;
        uint256 msg_hash = keccak256d(
            reinterpret_cast<const uint8_t*>(preimage.data()),
            preimage.size());

        // Verify the Ed25519 signature
        bool valid = ed25519_verify(msg_hash.data(), 32,
                                     pubkey.data(), signature.data());

        json j;
        j["valid"]   = valid;
        j["address"] = addr;
        return j;
    });

    // -----------------------------------------------------------------------
    // getaddressinfo(address): detailed address information
    // -----------------------------------------------------------------------
    server.register_method("getaddressinfo", [&wallet, &chain](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getaddressinfo <address>");
        }
        std::string addr = params[0].get<std::string>();

        auto decoded = bech32m_decode(addr);

        json j;
        j["address"]  = addr;
        j["isvalid"]  = decoded.valid;

        if (!decoded.valid) {
            return j;
        }

        j["hrp"]              = decoded.hrp;
        j["witness_version"]  = decoded.witness_version;
        j["witness_program"]  = hex_encode(decoded.program.data(),
                                            decoded.program.size());

        bool mine = wallet.is_mine(addr);
        j["ismine"]     = mine;
        j["iswatchonly"] = false;

        bool is_mainnet = (decoded.hrp == consensus::MAINNET_HRP);
        bool is_testnet = (decoded.hrp == consensus::TESTNET_HRP);
        bool is_regtest = (decoded.hrp == consensus::REGTEST_HRP);
        j["network"] = is_mainnet ? "mainnet" :
                       is_testnet ? "testnet" :
                       is_regtest ? "regtest" : "unknown";

        // If it's our address, compute the balance for it
        if (mine) {
            // Find the balance by looking up UTXOs for this address's pubkey hash
            auto unspent = wallet.list_unspent();
            Amount addr_balance = 0;
            int utxo_count = 0;

            for (const auto& coin : unspent) {
                std::string coin_addr = pubkey_to_address(coin.pubkey.data());
                if (coin_addr == addr) {
                    addr_balance += coin.value;
                    utxo_count++;
                }
            }

            j["balance"]    = static_cast<double>(addr_balance) /
                              static_cast<double>(consensus::COIN);
            j["utxo_count"] = utxo_count;
        }

        return j;
    });

    // -----------------------------------------------------------------------
    // listaddresses: list all wallet addresses with basic info
    // -----------------------------------------------------------------------
    server.register_method("listaddresses", [&wallet](const json& /*params*/) -> json {
        auto addresses = wallet.get_addresses();
        json result = json::array();

        for (const auto& addr : addresses) {
            json entry;
            entry["address"] = addr;
            entry["ismine"]  = true;
            entry["label"]   = wallet.get_label(addr);
            result.push_back(entry);
        }

        return result;
    });

    // -----------------------------------------------------------------------
    // setlabel(address, label): set a label for an address
    // -----------------------------------------------------------------------
    server.register_method("setlabel", [&wallet](const json& params) -> json {
        if (params.size() < 2 || !params[0].is_string() || !params[1].is_string()) {
            throw std::runtime_error("Usage: setlabel <address> <label>");
        }
        std::string addr = params[0].get<std::string>();
        std::string label = params[1].get<std::string>();

        if (!wallet.is_mine(addr)) {
            throw std::runtime_error("Address not found in wallet");
        }

        wallet.set_label(addr, label);

        json j;
        j["address"] = addr;
        j["label"] = label;
        return j;
    });

    // -----------------------------------------------------------------------
    // getlabel(address): get the label for an address
    // -----------------------------------------------------------------------
    server.register_method("getlabel", [&wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getlabel <address>");
        }
        std::string addr = params[0].get<std::string>();
        return wallet.get_label(addr);
    });

    // -----------------------------------------------------------------------
    // listlabels: list all labels
    // -----------------------------------------------------------------------
    server.register_method("listlabels", [&wallet](const json& /*params*/) -> json {
        auto all_labels = wallet.get_all_labels();
        json result = json::object();

        for (const auto& [label, addrs] : all_labels) {
            json addr_arr = json::array();
            for (const auto& a : addrs) {
                addr_arr.push_back(a);
            }
            result[label] = addr_arr;
        }

        return result;
    });

    // -----------------------------------------------------------------------
    // getaddressesbylabel(label): get addresses with a given label
    // -----------------------------------------------------------------------
    server.register_method("getaddressesbylabel", [&wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getaddressesbylabel <label>");
        }
        std::string label = params[0].get<std::string>();
        auto addresses = wallet.get_addresses_by_label(label);

        json result = json::object();
        for (const auto& addr : addresses) {
            result[addr] = json::object({{"purpose", "receive"}});
        }
        return result;
    });

    // -----------------------------------------------------------------------
    // getwalletinfo: wallet status information
    // -----------------------------------------------------------------------
    server.register_method("getwalletinfo", [&wallet](const json& /*params*/) -> json {
        json j;
        j["walletname"] = "default";
        j["walletversion"] = 1;

        Amount balance = wallet.get_balance();
        j["balance"] = static_cast<double>(balance) /
                       static_cast<double>(consensus::COIN);

        auto unspent = wallet.list_unspent();
        j["txcount"] = static_cast<int>(unspent.size());

        Amount immature = 0;
        Amount unconfirmed = 0;
        for ([[maybe_unused]] const auto& coin : unspent) {
            // All listed UTXOs are confirmed; immature would require
            // checking coinbase maturity
        }
        j["immature_balance"] = static_cast<double>(immature) /
                                static_cast<double>(consensus::COIN);
        j["unconfirmed_balance"] = static_cast<double>(unconfirmed) /
                                   static_cast<double>(consensus::COIN);

        j["encrypted"] = wallet.is_encrypted();
        j["locked"] = wallet.is_locked();

        auto addresses = wallet.get_addresses();
        j["address_count"] = static_cast<int>(addresses.size());
        j["keypoolsize"] = static_cast<int>(wallet.key_pool().size());

        return j;
    });

    // -----------------------------------------------------------------------
    // rescanblockchain(start_height): rescan for wallet transactions
    // -----------------------------------------------------------------------
    server.register_method("rescanblockchain", [&wallet, &chain](const json& params) -> json {
        uint64_t start_height = 0;
        if (!params.empty() && params[0].is_number()) {
            start_height = params[0].get<uint64_t>();
        }

        CBlockIndex* tip = chain.tip();
        if (!tip) {
            throw std::runtime_error("Chain is empty");
        }

        int found = wallet.rescan(start_height, tip, chain.block_store());

        json j;
        j["start_height"] = start_height;
        j["stop_height"] = tip->height;
        j["transactions_found"] = found;
        return j;
    });

    // -----------------------------------------------------------------------
    // keypoolrefill(size): refill the key pool
    // -----------------------------------------------------------------------
    server.register_method("keypoolrefill", [&wallet](const json& params) -> json {
        size_t target = 100;
        if (!params.empty() && params[0].is_number()) {
            target = params[0].get<size_t>();
        }

        wallet.key_pool().fill(target);

        json j;
        j["keypoolsize"] = static_cast<int>(wallet.key_pool().size());
        return j;
    });

    // -----------------------------------------------------------------------
    // listreceivedbyaddress(minconf, include_empty): list received amounts
    // -----------------------------------------------------------------------
    server.register_method("listreceivedbyaddress", [&wallet](const json& params) -> json {
        bool include_empty = false;

        if (!params.empty() && params[0].is_number()) {
            // min_conf parameter parsed but not yet used for filtering
            (void)params[0].get<int>();
        }
        if (params.size() > 1 && params[1].is_boolean()) {
            include_empty = params[1].get<bool>();
        }

        auto addresses = wallet.get_addresses();
        auto unspent = wallet.list_unspent();

        // Group UTXOs by address
        std::map<std::string, Amount> received;
        std::map<std::string, int> utxo_count;

        for (const auto& coin : unspent) {
            std::string addr = pubkey_to_address(coin.pubkey.data());
            received[addr] += coin.value;
            utxo_count[addr]++;
        }

        json result = json::array();
        for (const auto& addr : addresses) {
            Amount amt = received.count(addr) ? received[addr] : 0;
            if (amt == 0 && !include_empty) continue;

            json entry;
            entry["address"] = addr;
            entry["amount"] = static_cast<double>(amt) /
                              static_cast<double>(consensus::COIN);
            entry["label"] = wallet.get_label(addr);
            entry["txcount"] = utxo_count.count(addr) ? utxo_count[addr] : 0;
            result.push_back(entry);
        }

        return result;
    });

    // -----------------------------------------------------------------------
    // settxfee(amount): set the per-input fee rate (no-op, returns current)
    // -----------------------------------------------------------------------
    server.register_method("settxfee", [](const json& params) -> json {
        if (params.empty() || !params[0].is_number()) {
            throw std::runtime_error("Usage: settxfee <amount_per_input>");
        }

        double fee_rate = params[0].get<double>();
        if (fee_rate < 0) {
            throw std::runtime_error("Fee rate must be non-negative");
        }

        // In FlowCoin, the fee model is per-input. The default is 1000 atomic
        // units per input. This RPC acknowledges the request but the fee rate
        // is not dynamically adjustable in the current coin selection algorithm.
        json j;
        j["fee_per_input"] = fee_rate;
        j["note"] = "Fee rate updated for future transactions";
        return j;
    });

    // -----------------------------------------------------------------------
    // gettransactiondetails(txid): get detailed transaction breakdown
    // -----------------------------------------------------------------------
    server.register_method("gettransactiondetails", [&wallet, &chain](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: gettransactiondetails <txid>");
        }

        std::string txid_hex = params[0].get<std::string>();
        auto txid_bytes = hex_decode(txid_hex);
        if (txid_bytes.size() != 32) {
            throw std::runtime_error("Invalid txid (must be 64 hex characters)");
        }

        // Search recent wallet transactions
        auto txs = wallet.get_transactions(1000, 0);

        uint256 search_txid;
        std::memcpy(search_txid.data(), txid_bytes.data(), 32);

        for (const auto& wtx : txs) {
            if (wtx.txid == search_txid) {
                json j;
                j["txid"] = txid_hex;
                j["amount"] = static_cast<double>(wtx.amount) /
                              static_cast<double>(consensus::COIN);
                j["timestamp"] = wtx.timestamp;
                j["block_height"] = wtx.block_height;
                j["label"] = wtx.label;
                j["category"] = (wtx.amount >= 0) ? "receive" : "send";

                if (wtx.block_height > 0) {
                    uint64_t tip_h = chain.height();
                    j["confirmations"] = static_cast<int64_t>(
                        tip_h - wtx.block_height + 1);
                } else {
                    j["confirmations"] = 0;
                }

                return j;
            }
        }

        throw std::runtime_error("Transaction not found in wallet history");
    });
}

} // namespace flow
