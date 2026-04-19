// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Hardcoded seed nodes for initial peer discovery.
// These are well-known, stable nodes operated by core developers and
// community members. They serve as bootstrap points for new nodes
// joining the network for the first time.
//
// DNS seeds provide dynamic peer lists resolved via standard DNS queries.
// Hardcoded seeds are used as a fallback when DNS resolution fails.

#ifndef FLOWCOIN_NET_SEEDS_H
#define FLOWCOIN_NET_SEEDS_H

#include <cstdint>
#include <string>
#include <vector>

namespace flow {

// A single hardcoded seed node (IP or hostname + port)
struct SeedNode {
    const char* host;
    uint16_t port;
};

// ---------------------------------------------------------------------------
// Mainnet seeds: well-known stable nodes on the production network
// ---------------------------------------------------------------------------

const std::vector<SeedNode> MAINNET_SEEDS = {
    // ── DNS seeds (primary) ──────────────────────────────────
    // DNS is the primary discovery method. These hostnames resolve
    // to currently active nodes. As the network grows, more DNS
    // seeds will be added by community operators.
    {"seed.flowcoin.org",        9333},   // Multi-A/AAAA round-robin

    // ── Static IP fallback ───────────────────────────────────
    // Used when DNS resolution fails (firewall, censorship, etc.)
    // These are stable nodes operated by the core team.
    {"211.205.13.203",                          9333},   // Home seed (IPv4)
    {"188.137.182.41",                          9333},   // VPS seed (IPv4, NL)
    {"2a13:4ac0:20:7:f816:3eff:fe6f:5f83",      9333},   // VPS seed (IPv6, NL)
};

// ---------------------------------------------------------------------------
// Testnet seeds: nodes running the test network for development
// ---------------------------------------------------------------------------

const std::vector<SeedNode> TESTNET_SEEDS = {
    {"seed.flowcoin.org",        19333},  // Testnet on same host, different port
    {"211.205.13.203",           19333},
    {"188.137.182.41",           19333},
};

// ---------------------------------------------------------------------------
// Regtest seeds: empty (regtest is for local testing only)
// ---------------------------------------------------------------------------

const std::vector<SeedNode> REGTEST_SEEDS = {};

// ---------------------------------------------------------------------------
// DNS seeds: hostnames that resolve to multiple peer addresses via DNS
// DNS seed operators run custom DNS servers that return A/AAAA records
// for currently active nodes on the network. This provides dynamic
// peer discovery without hardcoding specific IPs.
// ---------------------------------------------------------------------------

const std::vector<std::string> MAINNET_DNS_SEEDS = {
    // DNS seeds are queried first. Each hostname should resolve to
    // multiple A/AAAA records pointing to active FlowCoin nodes.
    // As the network grows, community operators can run DNS seed
    // servers and be added here.
    "seed.flowcoin.org",           // Primary DNS seed
};

const std::vector<std::string> TESTNET_DNS_SEEDS = {
    "seed.flowcoin.org",
};

const std::vector<std::string> REGTEST_DNS_SEEDS = {};

// ---------------------------------------------------------------------------
// Utility: get seeds for a given network magic
// ---------------------------------------------------------------------------

inline const std::vector<SeedNode>& GetSeeds(uint32_t magic) {
    // Import consensus magic values
    // MAINNET_MAGIC = 0x464C4F57
    // TESTNET_MAGIC = 0x54464C57
    // REGTEST_MAGIC = 0x52464C57
    if (magic == 0x464C4F57) return MAINNET_SEEDS;
    if (magic == 0x54464C57) return TESTNET_SEEDS;
    return REGTEST_SEEDS;
}

inline const std::vector<std::string>& GetDNSSeeds(uint32_t magic) {
    if (magic == 0x464C4F57) return MAINNET_DNS_SEEDS;
    if (magic == 0x54464C57) return TESTNET_DNS_SEEDS;
    return REGTEST_DNS_SEEDS;
}

} // namespace flow

#endif // FLOWCOIN_NET_SEEDS_H
