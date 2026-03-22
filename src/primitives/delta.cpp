// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "delta.h"
#include "core/hash.h"

namespace flow {

std::vector<uint8_t> DeltaPayload::serialize() const {
    VectorWriter w;
    w.write_bytes(std::span<const uint8_t>(parent_model_hash.bytes(), 32));
    w.write_bytes(std::span<const uint8_t>(child_model_hash.bytes(), 32));
    w.write_u32(train_steps);
    w.write_float(loss_before);
    w.write_float(loss_after);
    w.write_compact_size(compressed_delta.size());
    if (!compressed_delta.empty()) {
        w.write_bytes(compressed_delta);
    }
    return w.release();
}

DeltaPayload DeltaPayload::deserialize(SpanReader& reader) {
    DeltaPayload d;
    reader.read_bytes(d.parent_model_hash.bytes(), 32);
    reader.read_bytes(d.child_model_hash.bytes(), 32);
    d.train_steps = reader.read_u32();
    d.loss_before = reader.read_float();
    d.loss_after = reader.read_float();
    uint64_t delta_size = reader.read_compact_size();
    d.compressed_delta.resize(delta_size);
    if (delta_size > 0) {
        reader.read_bytes(d.compressed_delta.data(), delta_size);
    }
    return d;
}

Hash256 DeltaPayload::get_hash() const {
    auto data = serialize();
    return keccak256d(data.data(), data.size());
}

} // namespace flow
