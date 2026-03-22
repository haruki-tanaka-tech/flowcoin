// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// DeltaPayload: the weight updates from training (Proof-of-Training).
// Miners train the model, produce weight deltas, and include them in blocks.
// Verifiers apply the deltas and check that val_loss matches.

#pragma once

#include "core/types.h"
#include "core/serialize.h"

#include <vector>

namespace flow {

struct DeltaPayload {
    Hash256  parent_model_hash; // model state before training
    Hash256  child_model_hash;  // model state after applying delta
    uint32_t train_steps{0};    // number of SGD steps performed
    float    loss_before{0.0f}; // validation loss before training
    float    loss_after{0.0f};  // validation loss after training
    std::vector<uint8_t> compressed_delta; // compressed weight updates

    // Serialize the payload
    std::vector<uint8_t> serialize() const;

    // Deserialize from a reader
    static DeltaPayload deserialize(SpanReader& reader);

    // Hash of the delta payload (used in block header delta_hash field)
    Hash256 get_hash() const;

    bool empty() const { return compressed_delta.empty(); }
};

} // namespace flow
