// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "crypto/bech32.h"
#include <cassert>
#include <cstring>
#include <stdexcept>

void test_bech32() {
    // Encode/decode round-trip with 20-byte program
    std::vector<uint8_t> program(20, 0x42);
    std::string encoded = flow::bech32m_encode("fl", 0, program);

    // Must start with "fl1"
    assert(encoded.substr(0, 3) == "fl1");

    // Should be all lowercase
    for (char c : encoded) {
        assert(c == std::tolower(c) || (c >= '0' && c <= '9'));
    }

    // Decode
    auto decoded = flow::bech32m_decode(encoded);
    assert(decoded.valid);
    assert(decoded.hrp == "fl");
    assert(decoded.witness_version == 0);
    assert(decoded.program == program);

    // Different program produces different encoding
    std::vector<uint8_t> program2(20, 0x43);
    std::string encoded2 = flow::bech32m_encode("fl", 0, program2);
    assert(encoded != encoded2);

    // Decode the second address
    auto decoded2 = flow::bech32m_decode(encoded2);
    assert(decoded2.valid);
    assert(decoded2.program == program2);

    // Invalid: wrong checksum
    std::string bad = encoded;
    bad.back() = (bad.back() == 'q') ? 'p' : 'q';
    auto bad_decoded = flow::bech32m_decode(bad);
    assert(!bad_decoded.valid);

    // Invalid: empty string
    auto empty_decoded = flow::bech32m_decode("");
    assert(!empty_decoded.valid);

    // pubkey_to_address round-trip
    uint8_t pubkey[32];
    for (int i = 0; i < 32; i++) pubkey[i] = static_cast<uint8_t>(i);
    std::string addr = flow::pubkey_to_address(pubkey);
    assert(addr.substr(0, 3) == "fl1");

    // Decode the address
    auto addr_decoded = flow::bech32m_decode(addr);
    assert(addr_decoded.valid);
    assert(addr_decoded.program.size() == 20);

    // Same pubkey produces same address
    std::string addr2 = flow::pubkey_to_address(pubkey);
    assert(addr == addr2);

    // Different pubkey produces different address
    uint8_t pubkey2[32];
    for (int i = 0; i < 32; i++) pubkey2[i] = static_cast<uint8_t>(31 - i);
    std::string addr3 = flow::pubkey_to_address(pubkey2);
    assert(addr != addr3);

    // Testnet HRP
    std::vector<uint8_t> tprog(20, 0x01);
    std::string taddr = flow::bech32m_encode("tfl", 0, tprog);
    assert(taddr.substr(0, 4) == "tfl1");
    auto tdec = flow::bech32m_decode(taddr);
    assert(tdec.valid);
    assert(tdec.hrp == "tfl");
    assert(tdec.program == tprog);
}
