// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "script/script.h"
#include "crypto/sign.h"
#include "hash/keccak.h"

#include <cstring>

namespace flow {
namespace script {

ScriptType classify(const std::vector<uint8_t>& script_pubkey) {
    if (script_pubkey.empty()) {
        return ScriptType::EMPTY;
    }
    if (script_pubkey.size() == PUBKEY_HASH_SIZE) {
        return ScriptType::P2PKH;
    }
    // Non-empty, non-standard size: treat as coinbase data
    return ScriptType::COINBASE;
}

std::vector<uint8_t> make_p2pkh(const std::array<uint8_t, 32>& pubkey_hash) {
    return std::vector<uint8_t>(pubkey_hash.begin(), pubkey_hash.end());
}

std::vector<uint8_t> make_p2pkh(const std::vector<uint8_t>& pubkey_hash) {
    if (pubkey_hash.size() != PUBKEY_HASH_SIZE) {
        return {};
    }
    return pubkey_hash;
}

std::vector<uint8_t> make_p2pkh_from_pubkey(const uint8_t* pubkey32) {
    uint256 hash = keccak256d(pubkey32, 32);
    return std::vector<uint8_t>(hash.data(), hash.data() + PUBKEY_HASH_SIZE);
}

std::vector<uint8_t> extract_pubkey_hash(const std::vector<uint8_t>& script_pubkey) {
    if (script_pubkey.size() != PUBKEY_HASH_SIZE) {
        return {};
    }
    return script_pubkey;
}

bool extract_pubkey_hash(const std::vector<uint8_t>& script_pubkey,
                         std::array<uint8_t, 32>& out) {
    if (script_pubkey.size() != PUBKEY_HASH_SIZE) {
        return false;
    }
    std::memcpy(out.data(), script_pubkey.data(), PUBKEY_HASH_SIZE);
    return true;
}

std::vector<uint8_t> make_script_sig(const uint8_t* signature64,
                                     const uint8_t* pubkey32) {
    std::vector<uint8_t> result(SCRIPT_SIG_SIZE);
    std::memcpy(result.data(), signature64, SIGNATURE_SIZE);
    std::memcpy(result.data() + SIGNATURE_SIZE, pubkey32, PUBKEY_SIZE);
    return result;
}

bool parse_script_sig(const std::vector<uint8_t>& script_sig,
                      const uint8_t*& sig_out,
                      const uint8_t*& pubkey_out) {
    if (script_sig.size() != SCRIPT_SIG_SIZE) {
        return false;
    }
    sig_out = script_sig.data();
    pubkey_out = script_sig.data() + SIGNATURE_SIZE;
    return true;
}

bool verify_script(const std::vector<uint8_t>& script_sig,
                   const std::vector<uint8_t>& script_pubkey,
                   const uint256& tx_hash) {
    // scriptSig must be 96 bytes: [64 sig][32 pubkey]
    if (script_sig.size() != SCRIPT_SIG_SIZE) {
        return false;
    }

    // scriptPubKey must be 32 bytes (pubkey hash)
    if (script_pubkey.size() != PUBKEY_HASH_SIZE) {
        return false;
    }

    const uint8_t* sig = script_sig.data();
    const uint8_t* pubkey = script_sig.data() + SIGNATURE_SIZE;

    // Verify pubkey hash: keccak256d(pubkey) must match script_pubkey
    uint256 pk_hash = keccak256d(pubkey, PUBKEY_SIZE);
    if (std::memcmp(pk_hash.data(), script_pubkey.data(), PUBKEY_HASH_SIZE) != 0) {
        return false;
    }

    // Verify Ed25519 signature over the transaction hash
    return ed25519_verify(tx_hash.data(), tx_hash.size(), pubkey, sig);
}

int count_sigops(const std::vector<uint8_t>& script) {
    // Each P2PKH output (32 bytes) represents 1 signature operation
    if (script.size() == PUBKEY_HASH_SIZE) {
        return 1;
    }
    return 0;
}

} // namespace script
} // namespace flow
