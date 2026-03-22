// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "protocol.h"

namespace flow::net {

std::vector<uint8_t> build_message(const std::string& command,
                                    const std::vector<uint8_t>& payload) {
    MessageHeader hdr;
    hdr.set_command(command);
    hdr.payload_size = static_cast<uint32_t>(payload.size());
    hdr.checksum = payload.empty() ? 0 : compute_checksum(payload.data(), payload.size());

    auto hdr_bytes = hdr.serialize();
    std::vector<uint8_t> msg;
    msg.reserve(HEADER_SIZE + payload.size());
    msg.insert(msg.end(), hdr_bytes.begin(), hdr_bytes.end());
    msg.insert(msg.end(), payload.begin(), payload.end());
    return msg;
}

std::vector<uint8_t> VersionMessage::serialize() const {
    VectorWriter w;
    w.write_u32(protocol_version);
    w.write_u64(best_height);
    w.write_i64(timestamp);
    return w.release();
}

VersionMessage VersionMessage::deserialize(const uint8_t* data, size_t len) {
    VersionMessage msg;
    SpanReader reader(std::span<const uint8_t>(data, len));
    msg.protocol_version = reader.read_u32();
    msg.best_height = reader.read_u64();
    msg.timestamp = reader.read_i64();
    return msg;
}

} // namespace flow::net
