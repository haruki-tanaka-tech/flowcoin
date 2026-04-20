// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "script/script.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "util/strencodings.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace flow {
namespace script {

// ===========================================================================
// Opcode names
// ===========================================================================

std::string opcode_name(Opcode op) {
    switch (op) {
        case OP_0:              return "OP_0";
        case OP_PUSHDATA1:      return "OP_PUSHDATA1";
        case OP_PUSHDATA2:      return "OP_PUSHDATA2";
        case OP_1NEGATE:        return "OP_1NEGATE";
        case OP_1:              return "OP_1";
        case OP_2:              return "OP_2";
        case OP_3:              return "OP_3";
        case OP_4:              return "OP_4";
        case OP_5:              return "OP_5";
        case OP_6:              return "OP_6";
        case OP_7:              return "OP_7";
        case OP_8:              return "OP_8";
        case OP_9:              return "OP_9";
        case OP_10:             return "OP_10";
        case OP_11:             return "OP_11";
        case OP_12:             return "OP_12";
        case OP_13:             return "OP_13";
        case OP_14:             return "OP_14";
        case OP_15:             return "OP_15";
        case OP_16:             return "OP_16";
        case OP_NOP:            return "OP_NOP";
        case OP_IF:             return "OP_IF";
        case OP_NOTIF:          return "OP_NOTIF";
        case OP_ELSE:           return "OP_ELSE";
        case OP_ENDIF:          return "OP_ENDIF";
        case OP_VERIFY:         return "OP_VERIFY";
        case OP_RETURN:         return "OP_RETURN";
        case OP_2DROP:          return "OP_2DROP";
        case OP_2DUP:           return "OP_2DUP";
        case OP_DROP:           return "OP_DROP";
        case OP_DUP:            return "OP_DUP";
        case OP_OVER:           return "OP_OVER";
        case OP_PICK:           return "OP_PICK";
        case OP_ROLL:           return "OP_ROLL";
        case OP_ROT:            return "OP_ROT";
        case OP_SWAP:           return "OP_SWAP";
        case OP_EQUAL:          return "OP_EQUAL";
        case OP_EQUALVERIFY:    return "OP_EQUALVERIFY";
        case OP_ADD:            return "OP_ADD";
        case OP_SUB:            return "OP_SUB";
        case OP_KECCAK256:      return "OP_KECCAK256";
        case OP_KECCAK256D:     return "OP_KECCAK256D";
        case OP_CHECKSIG:       return "OP_CHECKSIG";
        case OP_CHECKSIGVERIFY: return "OP_CHECKSIGVERIFY";
        case OP_CHECKMULTISIG:  return "OP_CHECKMULTISIG";
        case OP_CHECKMULTISIGVERIFY: return "OP_CHECKMULTISIGVERIFY";
        case OP_NOP1:           return "OP_NOP1";
        case OP_CHECKLOCKTIMEVERIFY: return "OP_CHECKLOCKTIMEVERIFY";
        case OP_CHECKSEQUENCEVERIFY: return "OP_CHECKSEQUENCEVERIFY";
        case OP_NOP4:           return "OP_NOP4";
        case OP_NOP5:           return "OP_NOP5";
        case OP_NOP6:           return "OP_NOP6";
        case OP_NOP7:           return "OP_NOP7";
        case OP_NOP8:           return "OP_NOP8";
        case OP_NOP9:           return "OP_NOP9";
        case OP_NOP10:          return "OP_NOP10";
        case OP_INVALIDOPCODE:  return "OP_INVALIDOPCODE";
        default: {
            // Data push opcode (1..75)
            if (op >= 0x01 && op <= 0x4b) {
                return "OP_PUSH" + std::to_string(op);
            }
            return "OP_UNKNOWN_" + std::to_string(op);
        }
    }
}

Opcode opcode_from_name(const std::string& name) {
    if (name == "OP_0" || name == "OP_FALSE") return OP_0;
    if (name == "OP_1" || name == "OP_TRUE") return OP_1;
    if (name == "OP_2") return OP_2;
    if (name == "OP_3") return OP_3;
    if (name == "OP_4") return OP_4;
    if (name == "OP_5") return OP_5;
    if (name == "OP_6") return OP_6;
    if (name == "OP_7") return OP_7;
    if (name == "OP_8") return OP_8;
    if (name == "OP_9") return OP_9;
    if (name == "OP_10") return OP_10;
    if (name == "OP_11") return OP_11;
    if (name == "OP_12") return OP_12;
    if (name == "OP_13") return OP_13;
    if (name == "OP_14") return OP_14;
    if (name == "OP_15") return OP_15;
    if (name == "OP_16") return OP_16;
    if (name == "OP_1NEGATE") return OP_1NEGATE;
    if (name == "OP_NOP") return OP_NOP;
    if (name == "OP_IF") return OP_IF;
    if (name == "OP_NOTIF") return OP_NOTIF;
    if (name == "OP_ELSE") return OP_ELSE;
    if (name == "OP_ENDIF") return OP_ENDIF;
    if (name == "OP_VERIFY") return OP_VERIFY;
    if (name == "OP_RETURN") return OP_RETURN;
    if (name == "OP_DUP") return OP_DUP;
    if (name == "OP_DROP") return OP_DROP;
    if (name == "OP_2DUP") return OP_2DUP;
    if (name == "OP_2DROP") return OP_2DROP;
    if (name == "OP_SWAP") return OP_SWAP;
    if (name == "OP_OVER") return OP_OVER;
    if (name == "OP_ROT") return OP_ROT;
    if (name == "OP_PICK") return OP_PICK;
    if (name == "OP_ROLL") return OP_ROLL;
    if (name == "OP_EQUAL") return OP_EQUAL;
    if (name == "OP_EQUALVERIFY") return OP_EQUALVERIFY;
    if (name == "OP_ADD") return OP_ADD;
    if (name == "OP_SUB") return OP_SUB;
    if (name == "OP_KECCAK256") return OP_KECCAK256;
    if (name == "OP_KECCAK256D") return OP_KECCAK256D;
    if (name == "OP_CHECKSIG") return OP_CHECKSIG;
    if (name == "OP_CHECKSIGVERIFY") return OP_CHECKSIGVERIFY;
    if (name == "OP_CHECKMULTISIG") return OP_CHECKMULTISIG;
    if (name == "OP_CHECKMULTISIGVERIFY") return OP_CHECKMULTISIGVERIFY;
    if (name == "OP_CHECKLOCKTIMEVERIFY") return OP_CHECKLOCKTIMEVERIFY;
    if (name == "OP_CHECKSEQUENCEVERIFY") return OP_CHECKSEQUENCEVERIFY;
    return OP_INVALIDOPCODE;
}

std::string script_type_name(ScriptType type) {
    switch (type) {
        case ScriptType::UNKNOWN:   return "nonstandard";
        case ScriptType::P2PKH:     return "pubkeyhash";
        case ScriptType::P2SH:      return "scripthash";
        case ScriptType::MULTISIG:  return "multisig";
        case ScriptType::NULL_DATA: return "nulldata";
        case ScriptType::COINBASE:  return "coinbase";
        case ScriptType::EMPTY:     return "empty";
        default:                    return "unknown";
    }
}

// ===========================================================================
// CScript -- builders
// ===========================================================================

CScript& CScript::push_data(const uint8_t* data, size_t len) {
    if (len == 0) {
        push_back(OP_0);
    } else if (len <= 75) {
        push_back(static_cast<uint8_t>(len));
        insert(end(), data, data + len);
    } else if (len <= 255) {
        push_back(OP_PUSHDATA1);
        push_back(static_cast<uint8_t>(len));
        insert(end(), data, data + len);
    } else if (len <= 65535) {
        push_back(OP_PUSHDATA2);
        push_back(static_cast<uint8_t>(len & 0xFF));
        push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        insert(end(), data, data + len);
    }
    return *this;
}

CScript& CScript::push_data(const std::vector<uint8_t>& data) {
    return push_data(data.data(), data.size());
}

CScript& CScript::push_int(int64_t value) {
    if (value == -1) {
        push_back(OP_1NEGATE);
    } else if (value == 0) {
        push_back(OP_0);
    } else if (value >= 1 && value <= 16) {
        push_back(static_cast<uint8_t>(OP_1 + value - 1));
    } else {
        // Encode as minimal script number
        std::vector<uint8_t> num;
        bool neg = value < 0;
        uint64_t abs_val = neg ? static_cast<uint64_t>(-value) : static_cast<uint64_t>(value);

        while (abs_val > 0) {
            num.push_back(static_cast<uint8_t>(abs_val & 0xFF));
            abs_val >>= 8;
        }

        // If the top bit is set, add a sign byte
        if (num.back() & 0x80) {
            num.push_back(neg ? 0x80 : 0x00);
        } else if (neg) {
            num.back() |= 0x80;
        }

        push_data(num);
    }
    return *this;
}

CScript& CScript::push_op(Opcode op) {
    push_back(static_cast<uint8_t>(op));
    return *this;
}

// ===========================================================================
// CScript -- standard script constructors
// ===========================================================================

CScript CScript::p2pkh(const std::vector<uint8_t>& pubkey_hash) {
    CScript s;
    s.push_op(OP_DUP);
    s.push_op(OP_KECCAK256D);
    s.push_data(pubkey_hash);
    s.push_op(OP_EQUALVERIFY);
    s.push_op(OP_CHECKSIG);
    return s;
}

CScript CScript::p2pkh(const std::array<uint8_t, 32>& pubkey_hash) {
    return p2pkh(std::vector<uint8_t>(pubkey_hash.begin(), pubkey_hash.end()));
}

CScript CScript::p2sh(const std::vector<uint8_t>& script_hash) {
    CScript s;
    s.push_op(OP_KECCAK256D);
    s.push_data(script_hash);
    s.push_op(OP_EQUAL);
    return s;
}

CScript CScript::multisig(int m, const std::vector<std::vector<uint8_t>>& pubkeys) {
    CScript s;
    s.push_int(m);
    for (const auto& pk : pubkeys) {
        s.push_data(pk);
    }
    s.push_int(static_cast<int64_t>(pubkeys.size()));
    s.push_op(OP_CHECKMULTISIG);
    return s;
}

CScript CScript::op_return(const std::vector<uint8_t>& data) {
    CScript s;
    s.push_op(OP_RETURN);
    if (!data.empty()) {
        s.push_data(data);
    }
    return s;
}

// ===========================================================================
// CScript -- analysis
// ===========================================================================

// P2PKH: OP_DUP OP_KECCAK256D <32 bytes> OP_EQUALVERIFY OP_CHECKSIG
// Total: 1 + 1 + 1 + 32 + 1 + 1 = 37 bytes
bool CScript::is_p2pkh() const {
    return size() == 37 &&
           (*this)[0] == OP_DUP &&
           (*this)[1] == OP_KECCAK256D &&
           (*this)[2] == 32 &&  // push 32 bytes
           (*this)[35] == OP_EQUALVERIFY &&
           (*this)[36] == OP_CHECKSIG;
}

// P2SH: OP_KECCAK256D <32 bytes> OP_EQUAL
// Total: 1 + 1 + 32 + 1 = 35 bytes
bool CScript::is_p2sh() const {
    return size() == 35 &&
           (*this)[0] == OP_KECCAK256D &&
           (*this)[1] == 32 &&  // push 32 bytes
           (*this)[34] == OP_EQUAL;
}

bool CScript::is_multisig(int& m, int& n) const {
    if (size() < 3) return false;

    // First byte: OP_m (OP_1..OP_16)
    uint8_t op_m = (*this)[0];
    if (op_m < OP_1 || op_m > OP_16) return false;
    m = op_m - OP_1 + 1;

    // Last byte: OP_CHECKMULTISIG
    if (back() != OP_CHECKMULTISIG) return false;

    // Second-to-last byte: OP_n (OP_1..OP_16)
    uint8_t op_n = (*this)[size() - 2];
    if (op_n < OP_1 || op_n > OP_16) return false;
    n = op_n - OP_1 + 1;

    if (m > n) return false;
    if (n > static_cast<int>(MAX_PUBKEYS_PER_MULTISIG)) return false;

    // Verify that n pubkeys follow OP_m, each pushed as 32 bytes
    size_t pos = 1;
    int pk_count = 0;
    while (pos < size() - 2) {
        if ((*this)[pos] != 32) return false;  // each pubkey is 32 bytes
        pos += 1 + 32;
        pk_count++;
    }

    return pk_count == n && pos == size() - 2;
}

bool CScript::is_op_return() const {
    return !empty() && (*this)[0] == OP_RETURN;
}

bool CScript::is_unspendable() const {
    if (!empty() && (*this)[0] == OP_RETURN) return true;
    if (size() > MAX_SCRIPT_SIZE) return true;
    return false;
}

ScriptType CScript::classify() const {
    if (empty()) return ScriptType::EMPTY;
    if (is_p2pkh()) return ScriptType::P2PKH;
    if (is_p2sh()) return ScriptType::P2SH;
    int m, n;
    if (is_multisig(m, n)) return ScriptType::MULTISIG;
    if (is_op_return()) return ScriptType::NULL_DATA;
    return ScriptType::UNKNOWN;
}

bool CScript::get_p2pkh_hash(std::vector<uint8_t>& hash) const {
    if (!is_p2pkh()) return false;
    hash.assign(begin() + 3, begin() + 3 + 32);
    return true;
}

bool CScript::get_p2sh_hash(std::vector<uint8_t>& hash) const {
    if (!is_p2sh()) return false;
    hash.assign(begin() + 2, begin() + 2 + 32);
    return true;
}

bool CScript::get_op_return_data(std::vector<uint8_t>& data) const {
    if (!is_op_return()) return false;
    if (size() <= 1) {
        data.clear();
        return true;
    }

    // Parse the data push after OP_RETURN
    size_t pos = 1;
    if (pos >= size()) {
        data.clear();
        return true;
    }

    uint8_t len_byte = (*this)[pos];
    pos++;

    if (len_byte <= 75) {
        // Direct push
        if (pos + len_byte > size()) return false;
        data.assign(begin() + pos, begin() + pos + len_byte);
    } else if (len_byte == OP_PUSHDATA1) {
        if (pos >= size()) return false;
        size_t len = (*this)[pos];
        pos++;
        if (pos + len > size()) return false;
        data.assign(begin() + pos, begin() + pos + len);
    } else if (len_byte == OP_PUSHDATA2) {
        if (pos + 1 >= size()) return false;
        size_t len = (*this)[pos] | (static_cast<size_t>((*this)[pos + 1]) << 8);
        pos += 2;
        if (pos + len > size()) return false;
        data.assign(begin() + pos, begin() + pos + len);
    } else {
        return false;
    }
    return true;
}

int CScript::count_sigops(bool accurate) const {
    int count = 0;
    size_t pos = 0;

    while (pos < size()) {
        uint8_t op = (*this)[pos];

        if (op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY) {
            count++;
        } else if (op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY) {
            if (accurate && pos > 0) {
                // Look at the previous opcode for OP_n
                uint8_t prev = (*this)[pos - 1];
                if (prev >= OP_1 && prev <= OP_16) {
                    count += prev - OP_1 + 1;
                } else {
                    count += MAX_PUBKEYS_PER_MULTISIG;
                }
            } else {
                count += MAX_PUBKEYS_PER_MULTISIG;
            }
        }

        // Skip data
        if (op >= 1 && op <= 75) {
            pos += 1 + op;
        } else if (op == OP_PUSHDATA1 && pos + 1 < size()) {
            pos += 2 + (*this)[pos + 1];
        } else if (op == OP_PUSHDATA2 && pos + 2 < size()) {
            uint16_t len = (*this)[pos + 1] | (static_cast<uint16_t>((*this)[pos + 2]) << 8);
            pos += 3 + len;
        } else {
            pos++;
        }
    }

    return count;
}

// ===========================================================================
// CScript -- serialization
// ===========================================================================

std::string CScript::to_asm() const {
    std::string result;
    size_t pos = 0;

    while (pos < size()) {
        if (!result.empty()) result += " ";

        uint8_t op = (*this)[pos];

        if (op >= 1 && op <= 75) {
            // Direct data push
            size_t len = op;
            pos++;
            if (pos + len > size()) {
                result += "[error]";
                break;
            }
            result += hex_encode(data() + pos, len);
            pos += len;
        } else if (op == OP_PUSHDATA1) {
            pos++;
            if (pos >= size()) { result += "[error]"; break; }
            size_t len = (*this)[pos];
            pos++;
            if (pos + len > size()) { result += "[error]"; break; }
            result += hex_encode(data() + pos, len);
            pos += len;
        } else if (op == OP_PUSHDATA2) {
            pos++;
            if (pos + 1 >= size()) { result += "[error]"; break; }
            size_t len = (*this)[pos] | (static_cast<size_t>((*this)[pos + 1]) << 8);
            pos += 2;
            if (pos + len > size()) { result += "[error]"; break; }
            result += hex_encode(data() + pos, len);
            pos += len;
        } else {
            result += opcode_name(static_cast<Opcode>(op));
            pos++;
        }
    }

    return result;
}

std::string CScript::to_hex() const {
    return hex_encode(data(), size());
}

CScript CScript::from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes = hex_decode(hex);
    CScript s;
    s.assign(bytes.begin(), bytes.end());
    return s;
}

// ===========================================================================
// Legacy compatibility functions
// ===========================================================================

ScriptType classify(const std::vector<uint8_t>& script_pubkey) {
    if (script_pubkey.empty()) {
        return ScriptType::EMPTY;
    }
    // Check if it matches the new CScript patterns
    CScript s;
    s.assign(script_pubkey.begin(), script_pubkey.end());
    ScriptType type = s.classify();
    if (type != ScriptType::UNKNOWN) return type;

    // Legacy: raw 32-byte hash is P2PKH
    if (script_pubkey.size() == PUBKEY_HASH_SIZE) {
        return ScriptType::P2PKH;
    }
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
    if (script.size() == PUBKEY_HASH_SIZE) {
        return 1;
    }
    CScript s;
    s.assign(script.begin(), script.end());
    return s.count_sigops(false);
}

// ===========================================================================
// Script interpreter helpers
// ===========================================================================

/** Convert a stack element to a boolean (empty or all-zero = false). */
static bool cast_to_bool(const std::vector<uint8_t>& elem) {
    for (size_t i = 0; i < elem.size(); ++i) {
        if (elem[i] != 0) {
            // Negative zero handling: last byte 0x80 with all others zero is false
            if (i == elem.size() - 1 && elem[i] == 0x80) {
                return false;
            }
            return true;
        }
    }
    return false;
}

/** Convert a stack element to a script number (int64_t). */
static bool script_num(const std::vector<uint8_t>& elem, int64_t& out,
                        size_t max_len = 4) {
    if (elem.size() > max_len) return false;
    if (elem.empty()) {
        out = 0;
        return true;
    }

    int64_t result = 0;
    for (size_t i = 0; i < elem.size(); ++i) {
        result |= static_cast<int64_t>(elem[i]) << (8 * i);
    }

    // Handle sign bit
    if (elem.back() & 0x80) {
        result &= ~(static_cast<int64_t>(0x80) << (8 * (elem.size() - 1)));
        result = -result;
    }

    out = result;
    return true;
}

/** Convert an int64_t to a script number stack element. */
static std::vector<uint8_t> num_to_elem(int64_t value) {
    if (value == 0) return {};

    std::vector<uint8_t> result;
    bool neg = value < 0;
    uint64_t abs_val = neg ? static_cast<uint64_t>(-value) : static_cast<uint64_t>(value);

    while (abs_val > 0) {
        result.push_back(static_cast<uint8_t>(abs_val & 0xFF));
        abs_val >>= 8;
    }

    if (result.back() & 0x80) {
        result.push_back(neg ? 0x80 : 0x00);
    } else if (neg) {
        result.back() |= 0x80;
    }

    return result;
}

// ===========================================================================
// Script interpreter
// ===========================================================================

bool ScriptInterpreter::eval(const CScript& script,
                              std::vector<std::vector<uint8_t>>& stack,
                              const uint256& tx_hash,
                              uint32_t flags,
                              std::string& error) {
    if (script.size() > MAX_SCRIPT_SIZE) {
        error = "script too large";
        return false;
    }

    size_t pos = 0;
    int op_count = 0;
    std::vector<bool> exec_stack;  // for IF/ELSE/ENDIF nesting
    bool executing = true;

    auto top = [&]() -> std::vector<uint8_t>& {
        return stack.back();
    };

    while (pos < script.size()) {
        uint8_t op = script[pos];

        // Determine if we are in an executing branch
        executing = true;
        for (bool b : exec_stack) {
            if (!b) { executing = false; break; }
        }

        // Data push opcodes (always parse, only push if executing)
        if (op >= 1 && op <= 75) {
            size_t len = op;
            pos++;
            if (pos + len > script.size()) {
                error = "push past end of script";
                return false;
            }
            if (executing) {
                if (stack.size() >= MAX_STACK_SIZE) {
                    error = "stack overflow";
                    return false;
                }
                stack.emplace_back(script.begin() + pos, script.begin() + pos + len);
            }
            pos += len;
            continue;
        }

        if (op == OP_PUSHDATA1) {
            pos++;
            if (pos >= script.size()) { error = "pushdata1 past end"; return false; }
            size_t len = script[pos];
            pos++;
            if (pos + len > script.size()) { error = "pushdata1 past end"; return false; }
            if (executing) {
                if (stack.size() >= MAX_STACK_SIZE) { error = "stack overflow"; return false; }
                stack.emplace_back(script.begin() + pos, script.begin() + pos + len);
            }
            pos += len;
            continue;
        }

        if (op == OP_PUSHDATA2) {
            pos++;
            if (pos + 1 >= script.size()) { error = "pushdata2 past end"; return false; }
            size_t len = script[pos] | (static_cast<size_t>(script[pos + 1]) << 8);
            pos += 2;
            if (pos + len > script.size()) { error = "pushdata2 past end"; return false; }
            if (executing) {
                if (stack.size() >= MAX_STACK_SIZE) { error = "stack overflow"; return false; }
                stack.emplace_back(script.begin() + pos, script.begin() + pos + len);
            }
            pos += len;
            continue;
        }

        pos++;

        // Non-push opcodes count toward the limit
        if (op > OP_16) {
            op_count++;
            if (op_count > static_cast<int>(MAX_OPS_PER_SCRIPT)) {
                error = "too many opcodes";
                return false;
            }
        }

        // Flow control opcodes are processed even in non-executing branches
        if (op == OP_IF || op == OP_NOTIF) {
            bool val = false;
            if (executing) {
                if (stack.empty()) { error = "IF with empty stack"; return false; }
                val = cast_to_bool(top());
                if (op == OP_NOTIF) val = !val;
                stack.pop_back();
            }
            exec_stack.push_back(executing ? val : false);
            continue;
        }
        if (op == OP_ELSE) {
            if (exec_stack.empty()) { error = "ELSE without IF"; return false; }
            // Only flip if the parent context is executing
            bool parent_exec = true;
            for (size_t i = 0; i + 1 < exec_stack.size(); ++i) {
                if (!exec_stack[i]) { parent_exec = false; break; }
            }
            if (parent_exec) {
                exec_stack.back() = !exec_stack.back();
            }
            continue;
        }
        if (op == OP_ENDIF) {
            if (exec_stack.empty()) { error = "ENDIF without IF"; return false; }
            exec_stack.pop_back();
            continue;
        }

        if (!executing) continue;

        // --- Execute opcode ---

        switch (op) {
        case OP_0:
            stack.push_back({});
            break;

        case OP_1NEGATE:
            stack.push_back({0x81});  // -1 as script number
            break;

        // OP_1 through OP_16
        case OP_1: case OP_2: case OP_3: case OP_4:
        case OP_5: case OP_6: case OP_7: case OP_8:
        case OP_9: case OP_10: case OP_11: case OP_12:
        case OP_13: case OP_14: case OP_15: case OP_16: {
            int val = op - OP_1 + 1;
            stack.push_back(num_to_elem(val));
            break;
        }

        case OP_NOP:
        case OP_NOP1:
        case OP_NOP4: case OP_NOP5: case OP_NOP6:
        case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
            break;

        case OP_CHECKLOCKTIMEVERIFY:
            if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) break;
            if (stack.empty()) { error = "CLTV with empty stack"; return false; }
            // Validation is done at transaction level, not here
            break;

        case OP_CHECKSEQUENCEVERIFY:
            if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) break;
            if (stack.empty()) { error = "CSV with empty stack"; return false; }
            break;

        case OP_VERIFY:
            if (stack.empty()) { error = "VERIFY with empty stack"; return false; }
            if (!cast_to_bool(top())) { error = "VERIFY failed"; return false; }
            stack.pop_back();
            break;

        case OP_RETURN:
            error = "OP_RETURN encountered";
            return false;

        // --- Stack operations ---

        case OP_DUP:
            if (stack.empty()) { error = "DUP with empty stack"; return false; }
            stack.push_back(top());
            break;

        case OP_DROP:
            if (stack.empty()) { error = "DROP with empty stack"; return false; }
            stack.pop_back();
            break;

        case OP_2DUP:
            if (stack.size() < 2) { error = "2DUP needs 2 elements"; return false; }
            stack.push_back(stack[stack.size() - 2]);
            stack.push_back(stack[stack.size() - 2]);
            break;

        case OP_2DROP:
            if (stack.size() < 2) { error = "2DROP needs 2 elements"; return false; }
            stack.pop_back();
            stack.pop_back();
            break;

        case OP_SWAP:
            if (stack.size() < 2) { error = "SWAP needs 2 elements"; return false; }
            std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
            break;

        case OP_OVER:
            if (stack.size() < 2) { error = "OVER needs 2 elements"; return false; }
            stack.push_back(stack[stack.size() - 2]);
            break;

        case OP_ROT:
            if (stack.size() < 3) { error = "ROT needs 3 elements"; return false; }
            {
                auto it = stack.end() - 3;
                std::rotate(it, it + 1, stack.end());
            }
            break;

        case OP_PICK: {
            if (stack.empty()) { error = "PICK with empty stack"; return false; }
            int64_t n;
            if (!script_num(top(), n)) { error = "PICK bad number"; return false; }
            stack.pop_back();
            if (n < 0 || static_cast<size_t>(n) >= stack.size()) {
                error = "PICK index out of range";
                return false;
            }
            stack.push_back(stack[stack.size() - 1 - static_cast<size_t>(n)]);
            break;
        }

        case OP_ROLL: {
            if (stack.empty()) { error = "ROLL with empty stack"; return false; }
            int64_t n;
            if (!script_num(top(), n)) { error = "ROLL bad number"; return false; }
            stack.pop_back();
            if (n < 0 || static_cast<size_t>(n) >= stack.size()) {
                error = "ROLL index out of range";
                return false;
            }
            size_t idx = stack.size() - 1 - static_cast<size_t>(n);
            auto elem = stack[idx];
            stack.erase(stack.begin() + static_cast<ptrdiff_t>(idx));
            stack.push_back(std::move(elem));
            break;
        }

        // --- Comparison ---

        case OP_EQUAL:
            if (stack.size() < 2) { error = "EQUAL needs 2 elements"; return false; }
            {
                auto b = stack.back(); stack.pop_back();
                auto a = stack.back(); stack.pop_back();
                stack.push_back(a == b ? num_to_elem(1) : std::vector<uint8_t>{});
            }
            break;

        case OP_EQUALVERIFY:
            if (stack.size() < 2) { error = "EQUALVERIFY needs 2 elements"; return false; }
            {
                auto b = stack.back(); stack.pop_back();
                auto a = stack.back(); stack.pop_back();
                if (a != b) { error = "EQUALVERIFY failed"; return false; }
            }
            break;

        // --- Arithmetic ---

        case OP_ADD: {
            if (stack.size() < 2) { error = "ADD needs 2 elements"; return false; }
            int64_t b_val, a_val;
            if (!script_num(stack.back(), b_val)) { error = "ADD bad number"; return false; }
            stack.pop_back();
            if (!script_num(stack.back(), a_val)) { error = "ADD bad number"; return false; }
            stack.pop_back();
            stack.push_back(num_to_elem(a_val + b_val));
            break;
        }

        case OP_SUB: {
            if (stack.size() < 2) { error = "SUB needs 2 elements"; return false; }
            int64_t b_val, a_val;
            if (!script_num(stack.back(), b_val)) { error = "SUB bad number"; return false; }
            stack.pop_back();
            if (!script_num(stack.back(), a_val)) { error = "SUB bad number"; return false; }
            stack.pop_back();
            stack.push_back(num_to_elem(a_val - b_val));
            break;
        }

        // --- Crypto ---

        case OP_KECCAK256: {
            if (stack.empty()) { error = "KECCAK256 with empty stack"; return false; }
            auto data = stack.back(); stack.pop_back();
            uint256 hash = keccak256(data);
            stack.emplace_back(hash.begin(), hash.end());
            break;
        }

        case OP_KECCAK256D: {
            if (stack.empty()) { error = "KECCAK256D with empty stack"; return false; }
            auto data = stack.back(); stack.pop_back();
            uint256 hash = keccak256d(data);
            stack.emplace_back(hash.begin(), hash.end());
            break;
        }

        case OP_CHECKSIG: {
            if (stack.size() < 2) { error = "CHECKSIG needs 2 elements"; return false; }
            auto pubkey = stack.back(); stack.pop_back();
            auto sig = stack.back(); stack.pop_back();

            if (pubkey.size() != 32 || sig.size() != 64) {
                stack.push_back({});  // false
            } else {
                bool valid = ed25519_verify(tx_hash.data(), tx_hash.size(),
                                            pubkey.data(), sig.data());
                stack.push_back(valid ? num_to_elem(1) : std::vector<uint8_t>{});
            }
            break;
        }

        case OP_CHECKSIGVERIFY: {
            if (stack.size() < 2) { error = "CHECKSIGVERIFY needs 2 elements"; return false; }
            auto pubkey = stack.back(); stack.pop_back();
            auto sig = stack.back(); stack.pop_back();

            if (pubkey.size() != 32 || sig.size() != 64) {
                error = "CHECKSIGVERIFY failed: invalid key/sig size";
                return false;
            }
            if (!ed25519_verify(tx_hash.data(), tx_hash.size(),
                                pubkey.data(), sig.data())) {
                error = "CHECKSIGVERIFY failed: bad signature";
                return false;
            }
            break;
        }

        case OP_CHECKMULTISIG: {
            if (stack.empty()) { error = "CHECKMULTISIG empty stack"; return false; }
            int64_t n_keys;
            if (!script_num(stack.back(), n_keys)) { error = "CHECKMULTISIG bad n"; return false; }
            stack.pop_back();
            if (n_keys < 0 || n_keys > static_cast<int64_t>(MAX_PUBKEYS_PER_MULTISIG)) {
                error = "CHECKMULTISIG n out of range";
                return false;
            }

            op_count += static_cast<int>(n_keys);
            if (op_count > static_cast<int>(MAX_OPS_PER_SCRIPT)) {
                error = "too many sigops in CHECKMULTISIG";
                return false;
            }

            if (static_cast<int64_t>(stack.size()) < n_keys) {
                error = "CHECKMULTISIG not enough pubkeys";
                return false;
            }

            std::vector<std::vector<uint8_t>> pubkeys;
            for (int64_t i = 0; i < n_keys; ++i) {
                pubkeys.push_back(stack.back());
                stack.pop_back();
            }

            if (stack.empty()) { error = "CHECKMULTISIG empty stack for m"; return false; }
            int64_t n_sigs;
            if (!script_num(stack.back(), n_sigs)) { error = "CHECKMULTISIG bad m"; return false; }
            stack.pop_back();
            if (n_sigs < 0 || n_sigs > n_keys) {
                error = "CHECKMULTISIG m out of range";
                return false;
            }

            if (static_cast<int64_t>(stack.size()) < n_sigs) {
                error = "CHECKMULTISIG not enough signatures";
                return false;
            }

            std::vector<std::vector<uint8_t>> sigs;
            for (int64_t i = 0; i < n_sigs; ++i) {
                sigs.push_back(stack.back());
                stack.pop_back();
            }

            // Null dummy (Bitcoin bug compatibility)
            if (flags & SCRIPT_VERIFY_NULLDUMMY) {
                if (!stack.empty() && !stack.back().empty()) {
                    error = "CHECKMULTISIG dummy not null";
                    return false;
                }
            }
            if (!stack.empty()) {
                stack.pop_back();  // pop dummy element
            }

            // Verify m-of-n: each sig must match a pubkey in order
            bool success = true;
            size_t pk_idx = 0;
            for (size_t s = 0; s < sigs.size() && success; ++s) {
                bool found = false;
                while (pk_idx < pubkeys.size()) {
                    if (sigs[s].size() == 64 && pubkeys[pk_idx].size() == 32) {
                        if (ed25519_verify(tx_hash.data(), tx_hash.size(),
                                           pubkeys[pk_idx].data(), sigs[s].data())) {
                            pk_idx++;
                            found = true;
                            break;
                        }
                    }
                    pk_idx++;
                }
                if (!found) success = false;
            }

            stack.push_back(success ? num_to_elem(1) : std::vector<uint8_t>{});
            break;
        }

        case OP_CHECKMULTISIGVERIFY: {
            // Re-use CHECKMULTISIG logic, then verify
            // For simplicity, push OP_CHECKMULTISIG result then check
            // This is a simplification -- in production, factor out the common logic
            error = "CHECKMULTISIGVERIFY not yet supported via interpreter path";
            return false;
        }

        default:
            error = "unknown opcode " + std::to_string(op);
            return false;
        }
    }

    // Check for unmatched IF/ELSE
    if (!exec_stack.empty()) {
        error = "unmatched IF";
        return false;
    }

    return true;
}

bool ScriptInterpreter::verify(const CScript& script_sig,
                                const CScript& script_pubkey,
                                const uint256& tx_hash,
                                uint32_t flags) {
    std::vector<std::vector<uint8_t>> stack;
    std::string error;

    // Step 1: Execute scriptSig
    if (!eval(script_sig, stack, tx_hash, flags, error)) {
        return false;
    }

    // Save the stack for P2SH evaluation
    std::vector<std::vector<uint8_t>> stack_copy = stack;

    // Step 2: Execute scriptPubKey on the resulting stack
    if (!eval(script_pubkey, stack, tx_hash, flags, error)) {
        return false;
    }

    // Stack must be non-empty and top must be true
    if (stack.empty() || !cast_to_bool(stack.back())) {
        return false;
    }

    // Step 3: P2SH validation (if enabled)
    if ((flags & SCRIPT_VERIFY_P2SH) && script_pubkey.is_p2sh()) {
        // The serialized script is the last element pushed by scriptSig
        if (stack_copy.empty()) return false;

        CScript serialized_script;
        serialized_script.assign(stack_copy.back().begin(), stack_copy.back().end());

        // Verify: keccak256d(serialized_script) must match the hash in scriptPubKey
        std::vector<uint8_t> script_hash;
        if (!script_pubkey.get_p2sh_hash(script_hash)) return false;

        uint256 computed_hash = keccak256d(serialized_script.data(), serialized_script.size());
        if (std::vector<uint8_t>(computed_hash.begin(), computed_hash.end()) != script_hash) {
            return false;
        }

        // Execute the deserialized script with the remaining stack
        stack_copy.pop_back();  // remove the serialized script
        if (!eval(serialized_script, stack_copy, tx_hash, flags, error)) {
            return false;
        }

        if (stack_copy.empty() || !cast_to_bool(stack_copy.back())) {
            return false;
        }
    }

    return true;
}

} // namespace script
} // namespace flow
