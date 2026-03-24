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
    // Core developer nodes (geographically distributed)
    {"seed1.flowcoin.org",       9333},
    {"seed2.flowcoin.org",       9333},
    {"seed3.flowcoin.org",       9333},
    {"seed4.flowcoin.org",       9333},

    // Community-operated seed nodes
    {"seed.flowcoin.network",    9333},
    {"node.flowcoin.dev",        9333},

    // Static IP fallback nodes (multiple continents)
    // North America
    {"45.33.32.156",             9333},
    {"104.237.137.109",          9333},
    // Europe
    {"85.214.107.77",            9333},
    {"138.201.82.166",           9333},
    {"176.9.50.14",              9333},
    // Asia-Pacific
    {"211.205.13.203",           9333},
    {"103.24.77.24",             9333},
    {"139.162.57.10",            9333},
    // South America
    {"191.232.38.12",            9333},
    // Africa
    {"41.185.8.16",              9333},
};

// ---------------------------------------------------------------------------
// Testnet seeds: nodes running the test network for development
// ---------------------------------------------------------------------------

const std::vector<SeedNode> TESTNET_SEEDS = {
    {"testseed1.flowcoin.org",   19333},
    {"testseed2.flowcoin.org",   19333},
    {"testnode.flowcoin.dev",    19333},
    {"45.33.32.156",             19333},
    {"85.214.107.77",            19333},
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
    "dnsseed.flowcoin.org",
    "seed.flowcoin.network",
    "dnsseed.flowcoin.dev",
    "seed.flowcoin.info",
};

const std::vector<std::string> TESTNET_DNS_SEEDS = {
    "testnet-seed.flowcoin.org",
    "testnet-seed.flowcoin.dev",
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
