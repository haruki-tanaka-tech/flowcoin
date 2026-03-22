// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "methods.h"
#include "consensus/params.h"
#include "wallet/coinselect.h"
#include "crypto/address.h"

namespace flow::rpc {

void register_blockchain_rpcs(RpcServer& server, ChainState& chain) {
    server.register_method("getblockcount", [&chain](const json&) -> json {
        return chain.height();
    });

    server.register_method("getbestblockhash", [&chain](const json&) -> json {
        auto tip = chain.tip();
        return tip ? tip->hash.to_hex() : "";
    });

    server.register_method("getblock", [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("getblock requires a block hash");
        }
        std::string hash_hex = params[0];
        auto hash = Hash256::from_hex(hash_hex);
        auto* idx = chain.block_tree().find(hash);
        if (!idx) {
            throw std::runtime_error("Block not found");
        }
        return json{
            {"hash", idx->hash.to_hex()},
            {"height", idx->height},
            {"timestamp", idx->timestamp},
            {"val_loss", idx->val_loss},
            {"nbits", idx->nbits},
            {"d_model", idx->d_model},
            {"n_layers", idx->n_layers},
            {"n_experts", idx->n_experts},
        };
    });

    server.register_method("gettraininginfo", [&chain](const json&) -> json {
        auto tip = chain.tip();
        if (!tip) return json{};
        return json{
            {"height", tip->height},
            {"val_loss", tip->val_loss},
            {"d_model", tip->d_model},
            {"n_layers", tip->n_layers},
            {"n_experts", tip->n_experts},
            {"improving_blocks", tip->improving_blocks},
        };
    });
}

void register_mempool_rpcs(RpcServer& server, Mempool& mempool) {
    server.register_method("getmempoolinfo", [&mempool](const json&) -> json {
        return json{
            {"size", mempool.size()},
            {"bytes", mempool.size_bytes()},
        };
    });
}

void register_wallet_rpcs(RpcServer& server, Wallet& wallet, ChainState& chain) {
    server.register_method("getnewaddress", [&wallet](const json&) -> json {
        return wallet.get_new_address();
    });

    server.register_method("getbalance", [&wallet, &chain](const json&) -> json {
        // Collect all pubkey hashes from wallet
        auto keys = wallet.get_all_keys();
        std::vector<Blob<20>> pkhs;
        pkhs.reserve(keys.size());
        for (const auto& wk : keys) {
            pkhs.push_back(wk.pubkey_hash);
        }

        // Scan UTXO set
        auto utxos = chain.utxo_set().find_by_pubkey_hashes(pkhs);
        int64_t balance = 0;
        for (const auto& u : utxos) {
            balance += u.entry.amount.value;
        }

        return json{
            {"balance", static_cast<double>(balance) / consensus::COIN},
            {"balance_sat", balance},
            {"utxo_count", utxos.size()},
        };
    });

    server.register_method("sendtoaddress", [&wallet, &chain](const json& params) -> json {
        if (params.size() < 2) {
            throw std::runtime_error("sendtoaddress <address> <amount>");
        }
        std::string dest_addr = params[0];
        double amount_flow = params[1].is_string()
            ? std::stod(params[1].get<std::string>())
            : params[1].get<double>();
        int64_t amount_sat = static_cast<int64_t>(amount_flow * consensus::COIN);

        // Decode destination address
        auto decoded = crypto::decode_address(dest_addr);
        if (!decoded) {
            throw std::runtime_error("invalid address: " + decoded.error_message());
        }
        if (decoded.value().pubkey_hash.size() != 20) {
            throw std::runtime_error("invalid address program length");
        }
        Blob<20> dest_pkh;
        std::memcpy(dest_pkh.bytes(), decoded.value().pubkey_hash.data(), 20);

        // Get our UTXOs
        auto keys = wallet.get_all_keys();
        std::vector<Blob<20>> pkhs;
        for (const auto& wk : keys) pkhs.push_back(wk.pubkey_hash);
        auto utxos = chain.utxo_set().find_by_pubkey_hashes(pkhs);

        // Convert to CoinEntry
        std::vector<CoinEntry> available;
        for (const auto& u : utxos) {
            available.push_back({u.outpoint, u.entry.amount, u.entry.pubkey_hash});
        }

        // Select coins
        auto selection = select_coins(available, Amount{amount_sat});
        if (!selection) {
            throw std::runtime_error(selection.error_message());
        }

        // Build transaction
        std::vector<COutPoint> inputs;
        std::vector<Blob<20>> input_pkhs;
        for (const auto& c : selection.value().selected) {
            inputs.push_back(c.outpoint);
            input_pkhs.push_back(c.pubkey_hash);
        }

        std::vector<CTxOut> outputs;
        CTxOut dest_out;
        dest_out.amount = Amount{amount_sat};
        dest_out.pubkey_hash = dest_pkh;
        outputs.push_back(dest_out);

        // Change output to a new address (never reuse)
        if (selection.value().change.value > 0) {
            std::string change_addr = wallet.get_new_address();
            auto change_decoded = crypto::decode_address(change_addr);
            CTxOut change_out;
            change_out.amount = selection.value().change;
            std::memcpy(change_out.pubkey_hash.bytes(),
                        change_decoded.value().pubkey_hash.data(), 20);
            outputs.push_back(change_out);
        }

        auto tx_result = wallet.create_transaction(inputs, input_pkhs, outputs);
        if (!tx_result) {
            throw std::runtime_error(tx_result.error_message());
        }

        return json{
            {"txid", tx_result.value().get_hash().to_hex()},
            {"amount", amount_flow},
            {"fee", static_cast<double>(selection.value().fee.value) / consensus::COIN},
        };
    });

    server.register_method("listaddresses", [&wallet](const json&) -> json {
        auto keys = wallet.get_all_keys();
        json result = json::array();
        for (const auto& wk : keys) {
            result.push_back(json{
                {"address", wk.address},
                {"index", wk.index},
                {"used", wk.used},
            });
        }
        return result;
    });

    server.register_method("importprivkey", [&wallet](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("importprivkey requires a hex private key");
        }
        std::string hex = params[0];
        auto privkey = PrivKey::from_hex(hex);
        if (privkey.is_zero()) {
            throw std::runtime_error("invalid private key");
        }
        auto result = wallet.import_privkey(privkey);
        if (!result) {
            throw std::runtime_error(result.error_message());
        }
        return result.value();
    });

    server.register_method("dumpwallet", [&wallet](const json&) -> json {
        auto keys = wallet.dump_keys();
        json result = json::array();
        for (const auto& [privkey_hex, address] : keys) {
            result.push_back(json{
                {"privkey", privkey_hex},
                {"address", address},
            });
        }
        return result;
    });
}

} // namespace flow::rpc
