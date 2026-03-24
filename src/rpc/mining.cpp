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
#include "consensus/growth.h"
#include "consensus/params.h"
#include "consensus/reward.h"
#include "util/strencodings.h"
#include "net/net.h"

#include <stdexcept>

namespace flow {

void register_mining_rpcs(RpcServer& server, ChainState& chain, NetManager& net) {

    // getblocktemplate: return a template for mining
    server.register_method("getblocktemplate", [&chain](const json& params) -> json {
        // Optional coinbase_address parameter
        std::string coinbase_addr;
        if (!params.empty() && params[0].is_string()) {
            coinbase_addr = params[0].get<std::string>();
        }

        BlockTemplate tmpl = create_block_template(chain, coinbase_addr);

        json j;
        j["height"]        = tmpl.header.height;
        j["previousblockhash"] = hex_encode(tmpl.header.prev_hash.data(), 32);
        j["nbits"]         = tmpl.header.nbits;
        j["timestamp"]     = tmpl.header.timestamp;
        j["version"]       = tmpl.header.version;

        // Target as hex for the miner
        arith_uint256 target;
        consensus::derive_target(tmpl.header.nbits, target);
        uint256 target_bytes = ArithToUint256(target);
        j["target"] = hex_encode(target_bytes.data(), 32);

        // Model dimensions
        json dims;
        dims["d_model"]     = tmpl.dims.d_model;
        dims["n_layers"]    = tmpl.dims.n_layers;
        dims["n_heads"]     = tmpl.dims.n_heads;
        dims["d_head"]      = tmpl.dims.d_head;
        dims["d_ff"]        = tmpl.dims.d_ff;
        dims["n_slots"]     = tmpl.dims.n_slots;
        dims["top_k"]       = tmpl.dims.top_k;
        dims["gru_dim"]     = tmpl.dims.gru_dim;
        dims["conv_kernel"] = tmpl.dims.conv_kernel;
        dims["vocab"]       = tmpl.dims.vocab;
        dims["seq_len"]     = tmpl.dims.seq_len;
        j["model"]          = dims;

        j["min_train_steps"] = tmpl.min_train_steps;

        // Coinbase transaction info
        j["coinbase_value"] = tmpl.coinbase_tx.get_value_out();

        // Coinbase tx as hex
        auto cb_data = tmpl.coinbase_tx.serialize();
        j["coinbase_tx"] = hex_encode(cb_data);

        // Previous block's val_loss for the miner
        CBlockIndex* tip = chain.tip();
        if (tip) {
            j["prev_val_loss"] = tip->val_loss;
        } else {
            j["prev_val_loss"] = consensus::MAX_VAL_LOSS;
        }

        return j;
    });

    // submitblock(hex): deserialize and submit a block
    server.register_method("submitblock", [&chain, &net](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: submitblock <hex_block_data>");
        }

        std::string hex_data = params[0].get<std::string>();
        auto block_bytes = hex_decode(hex_data);
        if (block_bytes.empty()) {
            throw std::runtime_error("Invalid hex data");
        }

        // Deserialize the block
        CBlock block;
        if (!deserialize_block(block_bytes, block)) {
            throw std::runtime_error("Failed to deserialize block");
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

    // getmininginfo: current mining status
    server.register_method("getmininginfo", [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();

        json j;
        j["blocks"]     = tip ? static_cast<int64_t>(tip->height) : 0;
        j["difficulty"]  = tip ? tip->nbits : consensus::INITIAL_NBITS;

        // Current reward
        uint64_t next_height = tip ? tip->height + 1 : 0;
        j["reward"] = static_cast<double>(consensus::compute_block_reward(next_height)) /
                      static_cast<double>(consensus::COIN);

        // Model dimensions at next height
        uint32_t improving = tip ? tip->improving_blocks : 0;
        auto dims = consensus::compute_growth(next_height, improving);
        j["d_model"]  = dims.d_model;
        j["n_layers"] = dims.n_layers;
        j["d_ff"]     = dims.d_ff;
        j["n_slots"]  = dims.n_slots;

        j["min_train_steps"] = consensus::compute_min_steps(next_height);
        j["chain"]   = "main";

        return j;
    });
}

} // namespace flow
