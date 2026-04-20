// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "script/standard.h"
#include "crypto/bech32.h"
#include "hash/keccak.h"

#include <cstring>

namespace flow {
namespace script {

// ===========================================================================
// Solver: determine script type and extract solutions
// ===========================================================================

ScriptType Solver(const CScript& script_pubkey,
                   std::vector<std::vector<uint8_t>>& solutions_out) {
    solutions_out.clear();

    if (script_pubkey.empty()) {
        return ScriptType::EMPTY;
    }

    // P2PKH: OP_DUP OP_KECCAK256D <32 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (script_pubkey.is_p2pkh()) {
        std::vector<uint8_t> hash;
        if (script_pubkey.get_p2pkh_hash(hash)) {
            solutions_out.push_back(std::move(hash));
        }
        return ScriptType::P2PKH;
    }

    // P2SH: OP_KECCAK256D <32 bytes> OP_EQUAL
    if (script_pubkey.is_p2sh()) {
        std::vector<uint8_t> hash;
        if (script_pubkey.get_p2sh_hash(hash)) {
            solutions_out.push_back(std::move(hash));
        }
        return ScriptType::P2SH;
    }

    // Multisig: OP_m <pubkey1> ... <pubkeyN> OP_n OP_CHECKMULTISIG
    int m, n;
    if (script_pubkey.is_multisig(m, n)) {
        // Push m as first solution
        solutions_out.push_back({static_cast<uint8_t>(m)});

        // Extract pubkeys
        size_t pos = 1;  // skip OP_m
        for (int i = 0; i < n; ++i) {
            if (pos >= script_pubkey.size() - 2) break;
            uint8_t pk_len = script_pubkey[pos];
            pos++;
            if (pos + pk_len > script_pubkey.size() - 2) break;
            solutions_out.emplace_back(script_pubkey.begin() + pos,
                                        script_pubkey.begin() + pos + pk_len);
            pos += pk_len;
        }
        return ScriptType::MULTISIG;
    }

    // OP_RETURN data carrier
    if (script_pubkey.is_op_return()) {
        std::vector<uint8_t> data;
        if (script_pubkey.get_op_return_data(data)) {
            solutions_out.push_back(std::move(data));
        }
        return ScriptType::NULL_DATA;
    }

    return ScriptType::UNKNOWN;
}

ScriptType Solver(const CScript& script_pubkey) {
    std::vector<std::vector<uint8_t>> solutions;
    return Solver(script_pubkey, solutions);
}

// ===========================================================================
// Standard transaction checks
// ===========================================================================

bool IsStandard(const CScript& script, std::string& reason) {
    // Size check
    if (script.size() > MAX_SCRIPT_SIZE) {
        reason = "scriptpubkey too large";
        return false;
    }

    ScriptType type = Solver(script);

    switch (type) {
        case ScriptType::P2PKH:
        case ScriptType::P2SH:
            return true;

        case ScriptType::MULTISIG: {
            int m, n;
            if (!script.is_multisig(m, n)) {
                reason = "malformed multisig";
                return false;
            }
            // Standard multisig: m <= 3, n <= 3
            if (n > 3) {
                reason = "too many multisig keys";
                return false;
            }
            return true;
        }

        case ScriptType::NULL_DATA: {
            std::vector<uint8_t> data;
            if (script.get_op_return_data(data) && data.size() <= MAX_OP_RETURN_DATA) {
                return true;
            }
            reason = "OP_RETURN data too large";
            return false;
        }

        case ScriptType::EMPTY:
            reason = "empty script";
            return false;

        case ScriptType::COINBASE:
        case ScriptType::UNKNOWN:
        default:
            reason = "non-standard script type";
            return false;
    }
}

bool IsStandard(const CScript& script) {
    std::string reason;
    return IsStandard(script, reason);
}

bool IsStandardScriptSig(const CScript& script_sig) {
    // A standard scriptSig contains only push operations
    size_t pos = 0;
    while (pos < script_sig.size()) {
        uint8_t op = script_sig[pos];

        if (op >= 1 && op <= 75) {
            pos += 1 + op;
        } else if (op == OP_PUSHDATA1) {
            if (pos + 1 >= script_sig.size()) return false;
            pos += 2 + script_sig[pos + 1];
        } else if (op == OP_PUSHDATA2) {
            if (pos + 2 >= script_sig.size()) return false;
            uint16_t len = script_sig[pos + 1] |
                           (static_cast<uint16_t>(script_sig[pos + 2]) << 8);
            pos += 3 + len;
        } else if (op == OP_0 || op == OP_1NEGATE ||
                   (op >= OP_1 && op <= OP_16)) {
            pos++;
        } else {
            // Non-push opcode found
            return false;
        }
    }
    return true;
}

// ===========================================================================
// Destination extraction
// ===========================================================================

TxDestination ExtractDestination(const CScript& script_pubkey,
                                  const std::string& hrp) {
    TxDestination dest;

    std::vector<std::vector<uint8_t>> solutions;
    dest.type = Solver(script_pubkey, solutions);

    switch (dest.type) {
        case ScriptType::P2PKH:
            if (!solutions.empty() && solutions[0].size() == 32) {
                dest.hash = solutions[0];
                // For P2PKH, the address uses the first 20 bytes of the hash
                // (the pubkey hash stored in the script is 32 bytes,
                //  but the Bech32m address uses 20 bytes)
                std::vector<uint8_t> program(solutions[0].begin(),
                                              solutions[0].begin() + 20);
                dest.address = bech32m_encode(hrp, 0, program);
            }
            break;

        case ScriptType::P2SH:
            if (!solutions.empty() && solutions[0].size() == 32) {
                dest.hash = solutions[0];
                std::vector<uint8_t> program(solutions[0].begin(),
                                              solutions[0].begin() + 20);
                dest.address = bech32m_encode(hrp, 0, program);
            }
            break;

        case ScriptType::MULTISIG:
            if (solutions.size() >= 2) {
                dest.multisig_m = solutions[0][0];
                dest.multisig_n = static_cast<int>(solutions.size()) - 1;
                for (size_t i = 1; i < solutions.size(); ++i) {
                    dest.pubkeys.push_back(solutions[i]);
                }
            }
            break;

        case ScriptType::NULL_DATA:
            if (!solutions.empty()) {
                dest.hash = solutions[0];  // the data payload
            }
            break;

        default:
            break;
    }

    return dest;
}

std::string ExtractAddress(const CScript& script_pubkey,
                            const std::string& hrp) {
    TxDestination dest = ExtractDestination(script_pubkey, hrp);
    return dest.address;
}

// ===========================================================================
// Script construction from destinations
// ===========================================================================

CScript GetScriptForDestination(const std::string& address) {
    Bech32mDecoded decoded = bech32m_decode(address);
    if (!decoded.valid) return CScript();

    if (decoded.witness_version != 0 || decoded.program.size() != 20) {
        return CScript();
    }

    // Expand the 20-byte program to a 32-byte hash by padding with zeros
    // (This is the reverse of the address creation process where we took
    //  the first 20 bytes of the 32-byte hash)
    // For script creation from address, we create a P2PKH with the 20-byte hash
    // stored in a 32-byte field (zero-padded)
    std::vector<uint8_t> pubkey_hash(32, 0);
    std::memcpy(pubkey_hash.data(), decoded.program.data(), 20);

    return CScript::p2pkh(pubkey_hash);
}

CScript GetScriptForPubKeyHash(const std::vector<uint8_t>& pubkey_hash) {
    if (pubkey_hash.size() != 32) return CScript();
    return CScript::p2pkh(pubkey_hash);
}

CScript GetScriptForPubKey(const std::vector<uint8_t>& pubkey) {
    if (pubkey.size() != 32) return CScript();

    // Hash the pubkey and create P2PKH
    uint256 hash = keccak256d(pubkey.data(), pubkey.size());
    std::vector<uint8_t> pubkey_hash(hash.begin(), hash.end());
    return CScript::p2pkh(pubkey_hash);
}

CScript MakeMultisigScript(int m, const std::vector<std::vector<uint8_t>>& pubkeys) {
    if (m < 1 || m > static_cast<int>(pubkeys.size())) return CScript();
    if (pubkeys.size() > MAX_PUBKEYS_PER_MULTISIG) return CScript();
    if (m > 16 || static_cast<int>(pubkeys.size()) > 16) return CScript();

    // Validate all pubkeys are 32 bytes
    for (const auto& pk : pubkeys) {
        if (pk.size() != 32) return CScript();
    }

    return CScript::multisig(m, pubkeys);
}

CScript GetScriptForP2SH(const CScript& redeem_script) {
    uint256 hash = keccak256d(redeem_script.data(), redeem_script.size());
    std::vector<uint8_t> script_hash(hash.begin(), hash.end());
    return CScript::p2sh(script_hash);
}

CScript GetScriptForNullData(const std::vector<uint8_t>& data) {
    if (data.size() > MAX_OP_RETURN_DATA) return CScript();
    return CScript::op_return(data);
}

// ===========================================================================
// Script utility functions
// ===========================================================================

uint256 ComputeScriptHash(const CScript& script) {
    return keccak256d(script.data(), script.size());
}

bool IsSingleSigScript(const CScript& script) {
    return script.is_p2pkh();
}

int GetMinRequiredSigs(const CScript& script) {
    if (script.is_p2pkh()) return 1;
    if (script.is_p2sh()) return 1;  // unknown, but at least 1

    int m, n;
    if (script.is_multisig(m, n)) return m;

    if (script.is_op_return()) return 0;

    return 0;
}

} // namespace script
} // namespace flow
