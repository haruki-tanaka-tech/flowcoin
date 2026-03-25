// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "rpc/training.h"
#include "rpc/server.h"
#include "chain/chainstate.h"
#include "chain/blockindex.h"
#include "chain/blockstore.h"
#include "consensus/growth.h"
#include "consensus/params.h"
#include "hash/keccak.h"
#include "util/strencodings.h"

#include <cmath>
#include <cstring>
#include <stdexcept>

namespace flow {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string training_hash_to_hex(const uint256& h) {
    return hex_encode(h.data(), 32);
}

static uint256 training_hex_to_hash(const std::string& hex_str) {
    auto bytes = hex_decode(hex_str);
    if (bytes.size() != 32) {
        throw std::runtime_error("Invalid hash length");
    }
    uint256 result;
    std::memcpy(result.data(), bytes.data(), 32);
    return result;
}

/// Estimate the total parameter count for a ResonanceNet V5 model
/// at the given dimensions.
static uint64_t estimate_param_count(const consensus::ModelDimensions& dims) {
    uint64_t d = dims.d_model;
    uint64_t L = dims.n_layers;
    uint64_t dff = dims.d_ff;
    uint64_t V = dims.vocab;
    uint64_t slots = dims.n_slots;

    // Embedding: V * d
    uint64_t embedding = V * d;

    // Per layer:
    //   QKV projection: 3 * d * d
    //   Output projection: d * d
    //   Feed-forward: d * dff + dff * d = 2 * d * dff
    //   minGRU: 3 * d * d (gates + candidate)
    //   Layer norms: 4 * d (2 norms * (scale + bias))
    //   Multi-scale conv: d * dims.conv_kernel
    uint64_t per_layer = 4 * d * d + 2 * d * dff + 3 * d * d + 4 * d
                       + d * dims.conv_kernel;

    // Slot memory: keys + values = 2 * slots * d
    uint64_t slot_mem = 2 * slots * d;

    // Output head: d * V
    uint64_t output_head = d * V;

    return embedding + L * per_layer + slot_mem + output_head;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void register_training_rpcs(RpcServer& server, ChainState& chain) {

    // gettraininginfo: current model training information from the tip block
    server.register_method("gettraininginfo",
        [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        if (!tip) {
            throw std::runtime_error("Chain is empty");
        }

        json j;
        j["height"]        = tip->height;
        j["val_loss"]      = tip->val_loss;
        j["prev_val_loss"] = tip->prev_val_loss;
        j["d_model"]       = tip->d_model;
        j["n_layers"]      = tip->n_layers;
        j["d_ff"]          = tip->d_ff;
        j["n_heads"]       = tip->n_heads;
        j["n_slots"]       = tip->n_slots;
        j["gru_dim"]       = tip->gru_dim;
        j["train_steps"]   = tip->train_steps;
        j["stagnation"]    = tip->stagnation_count;

        // Compute expected dimensions and param count
        consensus::ModelDimensions dims = consensus::compute_growth(
            tip->height);
        j["param_count"]   = estimate_param_count(dims);
        j["improving_blocks"] = tip->improving_blocks;

        // Compute the hash of the tip block's training proof
        j["training_hash"] = training_hash_to_hex(tip->hash);

        // Val loss history: walk back up to 20 blocks
        json loss_history = json::array();
        CBlockIndex* idx = tip;
        int count = 0;
        while (idx && count < 20) {
            json entry;
            entry["height"]   = idx->height;
            entry["val_loss"] = idx->val_loss;
            loss_history.push_back(entry);
            idx = idx->prev;
            count++;
        }
        j["loss_history"] = loss_history;

        return j;
    });

    // getmodelweights: full model weights as hex (WARNING: very large)
    // In practice, model weights are reconstructed from genesis + deltas.
    // This RPC returns the delta payload from the tip block, not the full
    // model state, since full model reconstruction requires the training
    // engine.
    server.register_method("getmodelweights",
        [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        if (!tip) {
            throw std::runtime_error("Chain is empty");
        }

        CBlock block;
        if (!chain.block_store().read_block(tip->pos, block)) {
            throw std::runtime_error("Failed to read tip block from disk");
        }

        json j;
        j["height"]        = tip->height;
        j["delta_length"]  = block.delta_payload.size();

        if (block.delta_payload.empty()) {
            j["hex"] = "";
        } else {
            j["hex"] = hex_encode(block.delta_payload);
        }

        // Hash of the delta payload
        if (!block.delta_payload.empty()) {
            uint256 delta_hash = keccak256(block.delta_payload);
            j["delta_hash"] = training_hash_to_hex(delta_hash);
        }

        return j;
    });

    // getmodelhash: keccak256 of the current model state (from tip)
    server.register_method("getmodelhash",
        [&chain](const json& /*params*/) -> json {
        CBlockIndex* tip = chain.tip();
        if (!tip) {
            throw std::runtime_error("Chain is empty");
        }

        // The model hash is effectively the cumulative training hash.
        // Each block's training_hash field binds the model state at that height.
        // We return the tip block's hash and training-related hashes.
        CBlock block;
        if (!chain.block_store().read_block(tip->pos, block)) {
            throw std::runtime_error("Failed to read tip block from disk");
        }

        json j;
        j["height"]        = tip->height;
        j["block_hash"]    = training_hash_to_hex(tip->hash);
        j["training_hash"] = training_hash_to_hex(block.training_hash);
        j["dataset_hash"]  = training_hash_to_hex(block.dataset_hash);

        // Hash the delta payload itself as a fingerprint
        if (!block.delta_payload.empty()) {
            uint256 dh = keccak256(block.delta_payload);
            j["delta_hash"] = training_hash_to_hex(dh);
        } else {
            j["delta_hash"] = std::string(64, '0');
        }

        return j;
    });

    // getdeltapayload(blockhash): return the delta payload from a specific block
    server.register_method("getdeltapayload",
        [&chain](const json& params) -> json {
        if (params.empty() || !params[0].is_string()) {
            throw std::runtime_error("Usage: getdeltapayload <blockhash>");
        }

        uint256 hash = training_hex_to_hash(params[0].get<std::string>());
        CBlockIndex* idx = chain.block_tree().find(hash);
        if (!idx) {
            throw std::runtime_error("Block not found");
        }

        CBlock block;
        if (!chain.block_store().read_block(idx->pos, block)) {
            throw std::runtime_error("Block data not available on disk");
        }

        json j;
        j["blockhash"]     = training_hash_to_hex(idx->hash);
        j["height"]        = idx->height;
        j["delta_length"]  = block.delta_payload.size();
        j["sparse_count"]  = block.sparse_count;
        j["sparse_threshold"] = block.sparse_threshold;

        if (!block.delta_payload.empty()) {
            j["hex"]        = hex_encode(block.delta_payload);
            uint256 dh      = keccak256(block.delta_payload);
            j["delta_hash"] = training_hash_to_hex(dh);
        } else {
            j["hex"]        = "";
            j["delta_hash"] = std::string(64, '0');
        }

        return j;
    });

    // getgrowthschedule(height): return the model dimensions at a given height
    server.register_method("getgrowthschedule",
        [](const json& params) -> json {
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

        consensus::ModelDimensions dims = consensus::compute_growth(height);
        uint32_t min_steps = consensus::compute_min_steps(height);

        json j;
        j["height"]       = height;
        j["d_model"]      = dims.d_model;
        j["n_layers"]     = dims.n_layers;
        j["n_heads"]      = dims.n_heads;
        j["d_head"]       = dims.d_head;
        j["d_ff"]         = dims.d_ff;
        j["n_slots"]      = dims.n_slots;
        j["top_k"]        = dims.top_k;
        j["gru_dim"]      = dims.gru_dim;
        j["conv_kernel"]  = dims.conv_kernel;
        j["vocab"]        = dims.vocab;
        j["seq_len"]      = dims.seq_len;
        j["min_steps"]    = min_steps;
        j["param_count"]  = estimate_param_count(dims);

        // Growth info
        bool dims_growing = (height < consensus::DIM_FREEZE_HEIGHT);
        j["phase"]         = dims_growing ? "dimension_growth" : "slot_growth";
        j["dims_frozen"]   = !dims_growing;

        return j;
    });

    // getvalidationdata: return metadata about the validation dataset
    // The actual dataset is embedded at compile time; this returns its hash
    // and dimensions for verification.
    server.register_method("getvalidationdata",
        [](const json& /*params*/) -> json {
        json j;
        j["eval_tokens"]  = consensus::EVAL_TOKENS;
        j["eval_seq_len"] = consensus::EVAL_SEQ_LEN;
        j["vocab_size"]   = consensus::GENESIS_VOCAB;

        // The dataset hash is verified per-block in consensus validation.
        // Here we return the expected parameters so miners can verify
        // their local dataset matches.
        j["info"] = "The validation dataset is the first "
                    + std::to_string(consensus::EVAL_TOKENS)
                    + " tokens of the consensus evaluation corpus. "
                    "Each forward pass uses a sequence length of "
                    + std::to_string(consensus::EVAL_SEQ_LEN) + ".";

        return j;
    });
}

} // namespace flow
