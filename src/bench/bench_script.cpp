// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Benchmarks for the script subsystem: P2PKH verification, multisig
// verification, script parsing, classification, and to_asm() formatting.

#include "bench.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "script/script.h"

#include <cstring>
#include <vector>

namespace flow::bench {

// ===========================================================================
// Script construction
// ===========================================================================

BENCH(Script_P2PKH_Create) {
    std::array<uint8_t, 32> pubkey_hash;
    std::memset(pubkey_hash.data(), 0xAB, 32);
    for (int i = 0; i < _iterations; i++) {
        pubkey_hash[0] = static_cast<uint8_t>(i & 0xFF);
        auto script = script::CScript::p2pkh(pubkey_hash);
        if (script.empty()) break;
    }
}

BENCH(Script_Multisig_Create_2of3) {
    std::vector<std::vector<uint8_t>> pubkeys(3);
    for (int j = 0; j < 3; j++) {
        pubkeys[j].resize(32);
        std::memset(pubkeys[j].data(), static_cast<int>(j + 1), 32);
    }
    for (int i = 0; i < _iterations; i++) {
        auto script = script::CScript::multisig(2, pubkeys);
        if (script.empty()) break;
    }
}

BENCH(Script_OpReturn_Create) {
    std::vector<uint8_t> data(80, 0x42);
    for (int i = 0; i < _iterations; i++) {
        data[0] = static_cast<uint8_t>(i & 0xFF);
        auto script = script::CScript::op_return(data);
        if (script.empty()) break;
    }
}

// ===========================================================================
// Script classification and parsing
// ===========================================================================

BENCH(Script_Classify_P2PKH) {
    std::array<uint8_t, 32> pubkey_hash;
    std::memset(pubkey_hash.data(), 0xAB, 32);
    auto script = script::CScript::p2pkh(pubkey_hash);
    for (int i = 0; i < _iterations; i++) {
        auto type = script.classify();
        if (type == script::ScriptType::UNKNOWN) break;
    }
}

BENCH(Script_Classify_Multisig) {
    std::vector<std::vector<uint8_t>> pubkeys(3);
    for (int j = 0; j < 3; j++) {
        pubkeys[j].resize(32);
        std::memset(pubkeys[j].data(), static_cast<int>(j + 1), 32);
    }
    auto script = script::CScript::multisig(2, pubkeys);
    for (int i = 0; i < _iterations; i++) {
        auto type = script.classify();
        if (type == script::ScriptType::UNKNOWN) break;
    }
}

BENCH(Script_ToAsm_P2PKH) {
    std::array<uint8_t, 32> pubkey_hash;
    std::memset(pubkey_hash.data(), 0xAB, 32);
    auto script = script::CScript::p2pkh(pubkey_hash);
    for (int i = 0; i < _iterations; i++) {
        std::string asm_str = script.to_asm();
        if (asm_str.empty()) break;
    }
}

BENCH(Script_ToAsm_Multisig) {
    std::vector<std::vector<uint8_t>> pubkeys(5);
    for (int j = 0; j < 5; j++) {
        pubkeys[j].resize(32);
        std::memset(pubkeys[j].data(), static_cast<int>(j + 1), 32);
    }
    auto script = script::CScript::multisig(3, pubkeys);
    for (int i = 0; i < _iterations; i++) {
        std::string asm_str = script.to_asm();
        if (asm_str.empty()) break;
    }
}

// ===========================================================================
// Script push operations
// ===========================================================================

BENCH(Script_PushData_Small) {
    std::vector<uint8_t> data(32, 0xCC);
    for (int i = 0; i < _iterations; i++) {
        script::CScript s;
        s.push_data(data);
        s.push_data(data);
        s.push_data(data);
        if (s.empty()) break;
    }
}

BENCH(Script_PushData_Large) {
    std::vector<uint8_t> data(256, 0xDD);
    for (int i = 0; i < _iterations; i++) {
        script::CScript s;
        s.push_data(data);
        if (s.empty()) break;
    }
}

BENCH(Script_PushInt) {
    for (int i = 0; i < _iterations; i++) {
        script::CScript s;
        for (int64_t v = -1; v <= 16; v++) {
            s.push_int(v);
        }
        s.push_int(1000);
        s.push_int(-1000);
        if (s.empty()) break;
    }
}

// ===========================================================================
// Script verification (P2PKH)
// ===========================================================================

BENCH(Script_VerifyP2PKH) {
    // Create a keypair
    KeyPair kp = generate_keypair();

    // Compute pubkey hash
    uint256 hash = keccak256d(kp.pubkey.data(), 32);
    std::array<uint8_t, 32> pubkey_hash;
    std::memcpy(pubkey_hash.data(), hash.data(), 32);

    // Build scriptPubKey
    auto script_pubkey = script::CScript::p2pkh(pubkey_hash);

    // Create a fake message to sign (simulating transaction hash)
    uint256 msg_hash;
    std::memset(msg_hash.data(), 0xBE, 32);
    auto sig = ed25519_sign(msg_hash.data(), 32, kp.privkey.data(), kp.pubkey.data());

    // Build scriptSig: <sig> <pubkey>
    std::vector<uint8_t> script_sig;
    script::CScript ss;
    ss.push_data(sig.data(), sig.size());
    ss.push_data(kp.pubkey.data(), kp.pubkey.size());
    script_sig.assign(ss.begin(), ss.end());

    std::vector<uint8_t> spk(script_pubkey.begin(), script_pubkey.end());

    for (int i = 0; i < _iterations; i++) {
        bool ok = script::verify_script(script_sig, spk, msg_hash);
        if (!ok) break;
    }
}

BENCH(Script_VerifyMultisig_2of3) {
    // Create 3 keypairs
    KeyPair keys[3];
    std::vector<std::vector<uint8_t>> pubkeys(3);
    for (int j = 0; j < 3; j++) {
        keys[j] = generate_keypair();
        pubkeys[j].assign(keys[j].pubkey.begin(), keys[j].pubkey.end());
    }

    auto script_pubkey = script::CScript::multisig(2, pubkeys);

    // Sign with first 2 keys
    uint256 msg_hash;
    std::memset(msg_hash.data(), 0xDE, 32);
    auto sig0 = ed25519_sign(msg_hash.data(), 32, keys[0].privkey.data(), keys[0].pubkey.data());
    auto sig1 = ed25519_sign(msg_hash.data(), 32, keys[1].privkey.data(), keys[1].pubkey.data());

    // Build scriptSig: OP_0 <sig0> <sig1>
    script::CScript ss;
    ss.push_op(script::OP_0);
    ss.push_data(sig0.data(), sig0.size());
    ss.push_data(sig1.data(), sig1.size());
    std::vector<uint8_t> script_sig(ss.begin(), ss.end());
    std::vector<uint8_t> spk(script_pubkey.begin(), script_pubkey.end());

    for (int i = 0; i < _iterations; i++) {
        bool ok = script::verify_script(script_sig, spk, msg_hash);
        if (!ok) break;
    }
}

// ===========================================================================
// Script P2SH construction
// ===========================================================================

BENCH(Script_P2SH_Create) {
    std::vector<uint8_t> script_hash(32, 0xDE);
    for (int i = 0; i < _iterations; i++) {
        script_hash[0] = static_cast<uint8_t>(i & 0xFF);
        auto script = script::CScript::p2sh(script_hash);
        if (script.empty()) break;
    }
}

// ===========================================================================
// Script serialization size
// ===========================================================================

BENCH(Script_SizeComputation_P2PKH) {
    std::array<uint8_t, 32> pubkey_hash;
    std::memset(pubkey_hash.data(), 0xAB, 32);
    auto script = script::CScript::p2pkh(pubkey_hash);
    for (int i = 0; i < _iterations; i++) {
        size_t sz = script.size();
        if (sz == 0) break;
    }
}

// ===========================================================================
// Script type name
// ===========================================================================

BENCH(Script_TypeName) {
    for (int i = 0; i < _iterations; i++) {
        auto name = script::script_type_name(
            static_cast<script::ScriptType>(i % 6));
        if (name.empty()) break;
    }
}

// ===========================================================================
// Opcode name lookup
// ===========================================================================

BENCH(Script_OpcodeName) {
    for (int i = 0; i < _iterations; i++) {
        auto name = script::opcode_name(
            static_cast<script::Opcode>(i & 0xFF));
        (void)name;
    }
}

BENCH(Script_OpcodeFromName) {
    std::vector<std::string> names = {
        "OP_DUP", "OP_KECCAK256D", "OP_EQUALVERIFY",
        "OP_CHECKSIG", "OP_RETURN", "OP_0",
        "OP_CHECKMULTISIG", "OP_IF", "OP_ELSE", "OP_ENDIF"
    };
    for (int i = 0; i < _iterations; i++) {
        auto op = script::opcode_from_name(names[i % names.size()]);
        if (op == script::OP_INVALIDOPCODE && names[i % names.size()] != "OP_INVALIDOPCODE") {
            // Some names might not be recognized
        }
    }
}

// ===========================================================================
// Multisig script creation (varying sizes)
// ===========================================================================

BENCH(Script_Multisig_1of1) {
    std::vector<std::vector<uint8_t>> pubkeys(1);
    pubkeys[0].resize(32);
    std::memset(pubkeys[0].data(), 0x11, 32);
    for (int i = 0; i < _iterations; i++) {
        auto script = script::CScript::multisig(1, pubkeys);
        if (script.empty()) break;
    }
}

BENCH(Script_Multisig_5of10) {
    std::vector<std::vector<uint8_t>> pubkeys(10);
    for (int j = 0; j < 10; j++) {
        pubkeys[j].resize(32);
        std::memset(pubkeys[j].data(), static_cast<int>(j + 1), 32);
    }
    for (int i = 0; i < _iterations; i++) {
        auto script = script::CScript::multisig(5, pubkeys);
        if (script.empty()) break;
    }
}

BENCH(Script_Multisig_10of15) {
    std::vector<std::vector<uint8_t>> pubkeys(15);
    for (int j = 0; j < 15; j++) {
        pubkeys[j].resize(32);
        std::memset(pubkeys[j].data(), static_cast<int>(j + 1), 32);
    }
    for (int i = 0; i < _iterations; i++) {
        auto script = script::CScript::multisig(10, pubkeys);
        if (script.empty()) break;
    }
}

// ===========================================================================
// Mixed script operations
// ===========================================================================

BENCH(Script_BuildAndClassify) {
    std::array<uint8_t, 32> pubkey_hash;
    std::memset(pubkey_hash.data(), 0xAB, 32);
    for (int i = 0; i < _iterations; i++) {
        pubkey_hash[0] = static_cast<uint8_t>(i & 0xFF);
        auto script = script::CScript::p2pkh(pubkey_hash);
        auto type = script.classify();
        std::string asm_str = script.to_asm();
        (void)type;
        (void)asm_str;
    }
}

} // namespace flow::bench
