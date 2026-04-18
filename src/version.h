// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Version constants for FlowCoin Core.

#ifndef FLOWCOIN_VERSION_H
#define FLOWCOIN_VERSION_H

#include <cstdint>

namespace flow {
namespace version {

    constexpr int MAJOR = 1;
    constexpr int MINOR = 0;
    constexpr int PATCH = 0;

    /// Numeric version: 10000 * major + 100 * minor + patch
    constexpr int CLIENT_VERSION = 10000 * MAJOR + 100 * MINOR + PATCH;

    constexpr const char* CLIENT_NAME           = "FlowCoin Core";
    constexpr const char* CLIENT_VERSION_STRING  = "1.0.0";
    constexpr const char* USER_AGENT             = "/FlowCoin:1.0.0/";
    constexpr const char* COPYRIGHT              = "Copyright (c) 2026 Kristian Pilatovich";
    constexpr const char* LICENSE                = "MIT License";
    constexpr const char* URL                    = "https://github.com/KristianPilatovich/flowcoin";

    /// Minimum supported peer protocol version.
    constexpr uint32_t MIN_PEER_VERSION = 10000;

} // namespace version
} // namespace flow

// Convenience macros for backward compatibility with existing code
static constexpr int CLIENT_VERSION_MAJOR = flow::version::MAJOR;
static constexpr int CLIENT_VERSION_MINOR = flow::version::MINOR;
static constexpr int CLIENT_VERSION_BUILD = flow::version::PATCH;
static constexpr const char* CLIENT_NAME = flow::version::CLIENT_NAME;
static constexpr const char* CLIENT_VERSION_STRING = flow::version::CLIENT_VERSION_STRING;

#endif // FLOWCOIN_VERSION_H
