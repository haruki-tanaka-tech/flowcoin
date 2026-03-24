// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "mining/submitblock.h"
#include "chain/chainstate.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "util/serialize.h"
#include "logging.h"

#include <cstring>

namespace flow {

SubmitResult submit_block(ChainState& chain, const CBlock& block) {
    SubmitResult result;

    consensus::ValidationState vstate;
    if (chain.accept_block(block, vstate)) {
        result.accepted = true;
        result.reject_reason.clear();
        LogInfo("mining", "Block accepted at height %lu", (unsigned long)block.height);
    } else {
        result.accepted = false;
        result.reject_reason = vstate.to_string();
        LogWarn("mining", "Block rejected at height %lu: %s",
                (unsigned long)block.height, result.reject_reason.c_str());
    }

    return result;
}

bool deserialize_block(const std::vector<uint8_t>& data, CBlock& block) {
    if (data.size() < 308) return false;  // minimum: header size

    DataReader r(data.data(), data.size());

    // Read the 244-byte unsigned header fields
    auto prev_hash_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.prev_hash.data(), prev_hash_bytes.data(), 32);

    auto merkle_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.merkle_root.data(), merkle_bytes.data(), 32);

    auto training_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.training_hash.data(), training_bytes.data(), 32);

    auto dataset_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.dataset_hash.data(), dataset_bytes.data(), 32);

    block.height           = r.read_u64_le();
    block.timestamp        = r.read_i64_le();
    block.nbits            = r.read_u32_le();
    block.val_loss         = r.read_float_le();
    block.prev_val_loss    = r.read_float_le();
    block.d_model          = r.read_u32_le();
    block.n_layers         = r.read_u32_le();
    block.d_ff             = r.read_u32_le();
    block.n_heads          = r.read_u32_le();
    block.gru_dim          = r.read_u32_le();
    block.n_slots          = r.read_u32_le();
    block.train_steps      = r.read_u32_le();
    block.stagnation       = r.read_u32_le();
    block.delta_offset     = r.read_u32_le();
    block.delta_length     = r.read_u32_le();
    block.sparse_count     = r.read_u32_le();
    block.sparse_threshold = r.read_float_le();
    block.nonce            = r.read_u32_le();
    block.version          = r.read_u32_le();

    auto pubkey_bytes = r.read_bytes(32);
    if (r.error()) return false;
    std::memcpy(block.miner_pubkey.data(), pubkey_bytes.data(), 32);

    auto sig_bytes = r.read_bytes(64);
    if (r.error()) return false;
    std::memcpy(block.miner_sig.data(), sig_bytes.data(), 64);

    // If we only have the header, that's fine (no transactions or delta)
    if (r.remaining() == 0) return true;

    // Transaction count
    uint64_t tx_count = r.read_compact_size();
    if (r.error() || tx_count > 100000) return false;

    block.vtx.resize(static_cast<size_t>(tx_count));
    for (uint64_t i = 0; i < tx_count; ++i) {
        CTransaction& tx = block.vtx[i];

        tx.version = r.read_u32_le();

        uint64_t vin_count = r.read_compact_size();
        if (r.error() || vin_count > 10000) return false;

        tx.vin.resize(static_cast<size_t>(vin_count));
        for (uint64_t j = 0; j < vin_count; ++j) {
            auto txid_bytes = r.read_bytes(32);
            if (r.error()) return false;
            std::memcpy(tx.vin[j].prevout.txid.data(), txid_bytes.data(), 32);
            tx.vin[j].prevout.index = r.read_u32_le();

            auto pk_bytes = r.read_bytes(32);
            if (r.error()) return false;
            std::memcpy(tx.vin[j].pubkey.data(), pk_bytes.data(), 32);

            auto sig_b = r.read_bytes(64);
            if (r.error()) return false;
            std::memcpy(tx.vin[j].signature.data(), sig_b.data(), 64);
        }

        uint64_t vout_count = r.read_compact_size();
        if (r.error() || vout_count > 10000) return false;

        tx.vout.resize(static_cast<size_t>(vout_count));
        for (uint64_t j = 0; j < vout_count; ++j) {
            tx.vout[j].amount = r.read_i64_le();
            auto pkh_bytes = r.read_bytes(32);
            if (r.error()) return false;
            std::memcpy(tx.vout[j].pubkey_hash.data(), pkh_bytes.data(), 32);
        }

        tx.locktime = r.read_i64_le();
        if (r.error()) return false;
    }

    // Delta payload
    uint64_t delta_len = r.read_compact_size();
    if (r.error()) return false;
    if (delta_len > consensus::MAX_DELTA_SIZE) return false;

    if (delta_len > 0) {
        auto delta_bytes = r.read_bytes(static_cast<size_t>(delta_len));
        if (r.error()) return false;
        block.delta_payload = std::move(delta_bytes);
    }

    return true;
}

} // namespace flow
