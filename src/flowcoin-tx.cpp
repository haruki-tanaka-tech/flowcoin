// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// flowcoin-tx: Offline transaction creation and signing utility.
// Creates, modifies, and signs FlowCoin transactions without requiring
// a running node. All operations work on raw transaction hex.
//
// Usage:
//   flowcoin-tx -create [commands...]
//   flowcoin-tx <hex-tx> [commands...]
//
// Commands:
//   in=TXID:VOUT              Add an input spending TXID output VOUT
//   outaddr=VALUE:ADDRESS     Add output of VALUE FLOW to ADDRESS
//   outdata=HEX               Add OP_RETURN data output
//   sign=PRIVKEY[:INPUT]      Sign input with Ed25519 hex private key
//                             If :INPUT is omitted, sign all inputs
//   set=version:N             Set transaction version
//   set=locktime:N            Set locktime
//   delin=N                   Delete input at index N
//   delout=N                  Delete output at index N
//
// Options:
//   -create                   Create a new empty transaction
//   -json                     Output as JSON instead of hex
//   -txid                     Output only the transaction ID
//   --help, -h                Print help
//
// Examples:
//   flowcoin-tx -create in=abc...def:0 outaddr=10.0:fl1q... sign=<hex-privkey>
//   flowcoin-tx <hex> sign=abc...def
//   flowcoin-tx -create -json in=abc...def:0 outaddr=50.0:fl1q...

#include "crypto/bech32.h"
#include "crypto/keys.h"
#include "crypto/sign.h"
#include "hash/keccak.h"
#include "primitives/transaction.h"
#include "util/strencodings.h"
#include "util/types.h"
#include "version.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// ============================================================================
// Utility helpers
// ============================================================================

static bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static std::string trim_ws(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

/// Convert a FLOW amount string (e.g. "10.5") to atomic units.
static int64_t parse_amount(const std::string& s) {
    // Find the decimal point
    auto dot = s.find('.');
    int64_t whole = 0;
    int64_t frac = 0;

    if (dot == std::string::npos) {
        // No decimal point — whole number
        try {
            whole = std::stoll(s);
        } catch (...) {
            std::cerr << "error: invalid amount '" << s << "'" << std::endl;
            std::exit(1);
        }
        return whole * 100'000'000LL;
    }

    // Parse whole part
    if (dot > 0) {
        try {
            whole = std::stoll(s.substr(0, dot));
        } catch (...) {
            std::cerr << "error: invalid amount '" << s << "'" << std::endl;
            std::exit(1);
        }
    }

    // Parse fractional part (up to 8 digits)
    std::string frac_str = s.substr(dot + 1);
    if (frac_str.size() > 8) {
        std::cerr << "error: too many decimal places in amount '" << s
                  << "' (max 8)" << std::endl;
        std::exit(1);
    }

    // Pad to 8 digits
    while (frac_str.size() < 8) {
        frac_str.push_back('0');
    }

    try {
        frac = std::stoll(frac_str);
    } catch (...) {
        std::cerr << "error: invalid fractional amount in '" << s << "'" << std::endl;
        std::exit(1);
    }

    int64_t result = whole * 100'000'000LL + frac;
    if (whole < 0) result = whole * 100'000'000LL - frac;
    return result;
}

/// Format atomic units as a FLOW amount string (e.g. "10.50000000").
static std::string format_amount(int64_t atomic) {
    bool negative = atomic < 0;
    if (negative) atomic = -atomic;

    int64_t whole = atomic / 100'000'000LL;
    int64_t frac = atomic % 100'000'000LL;

    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s%lld.%08lld",
                  negative ? "-" : "",
                  static_cast<long long>(whole),
                  static_cast<long long>(frac));
    return std::string(buf);
}

/// Decode a hex-encoded uint256 (64 hex chars, big-endian display to little-endian bytes).
static flow::uint256 decode_txid(const std::string& hex) {
    if (hex.size() != 64) {
        std::cerr << "error: txid must be 64 hex characters (got "
                  << hex.size() << ")" << std::endl;
        std::exit(1);
    }

    std::vector<uint8_t> bytes = flow::hex_decode(hex);
    if (bytes.size() != 32) {
        std::cerr << "error: invalid hex in txid '" << hex << "'" << std::endl;
        std::exit(1);
    }

    // Reverse byte order (display is big-endian, internal is little-endian)
    std::reverse(bytes.begin(), bytes.end());

    flow::uint256 result;
    std::memcpy(result.data(), bytes.data(), 32);
    return result;
}

/// Encode a uint256 as a hex string (big-endian display).
static std::string encode_txid(const flow::uint256& txid) {
    return flow::hex_encode_reverse<32>(txid.data());
}

// ============================================================================
// Transaction serialization / deserialization
// ============================================================================

/// Serialize a transaction to raw bytes.
static std::vector<uint8_t> serialize_tx(const flow::CTransaction& tx) {
    return tx.serialize();
}

/// Deserialize a transaction from raw bytes.
static bool deserialize_tx(const std::vector<uint8_t>& data, flow::CTransaction& tx) {
    if (data.size() < 12) return false;  // minimum: version(4) + vin_count(4) + vout_count(4)

    size_t offset = 0;

    auto read_u32 = [&]() -> uint32_t {
        if (offset + 4 > data.size()) return 0;
        uint32_t v = 0;
        std::memcpy(&v, data.data() + offset, 4);
        offset += 4;
        return v;
    };

    auto read_i64 = [&]() -> int64_t {
        if (offset + 8 > data.size()) return 0;
        int64_t v = 0;
        std::memcpy(&v, data.data() + offset, 8);
        offset += 8;
        return v;
    };

    auto read_bytes = [&](uint8_t* dst, size_t n) {
        if (offset + n > data.size()) return false;
        std::memcpy(dst, data.data() + offset, n);
        offset += n;
        return true;
    };

    tx.version = read_u32();

    uint32_t vin_count = read_u32();
    if (vin_count > 10000) return false;  // sanity check

    tx.vin.resize(vin_count);
    for (uint32_t i = 0; i < vin_count; ++i) {
        if (!read_bytes(tx.vin[i].prevout.txid.data(), 32)) return false;
        tx.vin[i].prevout.index = read_u32();
        if (!read_bytes(tx.vin[i].signature.data(), 64)) return false;
        if (!read_bytes(tx.vin[i].pubkey.data(), 32)) return false;
    }

    uint32_t vout_count = read_u32();
    if (vout_count > 10000) return false;

    tx.vout.resize(vout_count);
    for (uint32_t i = 0; i < vout_count; ++i) {
        tx.vout[i].amount = read_i64();
        if (!read_bytes(tx.vout[i].pubkey_hash.data(), 32)) return false;
    }

    tx.locktime = read_i64();
    return true;
}

// ============================================================================
// Transaction JSON output
// ============================================================================

static std::string tx_to_json(const flow::CTransaction& tx) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"txid\": \"" << encode_txid(tx.get_txid()) << "\",\n";
    ss << "  \"version\": " << tx.version << ",\n";
    ss << "  \"locktime\": " << tx.locktime << ",\n";

    ss << "  \"vin\": [\n";
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& in = tx.vin[i];
        ss << "    {\n";
        if (in.is_coinbase()) {
            ss << "      \"coinbase\": true\n";
        } else {
            ss << "      \"txid\": \"" << encode_txid(in.prevout.txid) << "\",\n";
            ss << "      \"vout\": " << in.prevout.index << ",\n";
            ss << "      \"signature\": \"" << flow::hex_encode(in.signature.data(), 64) << "\",\n";
            ss << "      \"pubkey\": \"" << flow::hex_encode(in.pubkey.data(), 32) << "\"\n";
        }
        ss << "    }" << (i + 1 < tx.vin.size() ? "," : "") << "\n";
    }
    ss << "  ],\n";

    ss << "  \"vout\": [\n";
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& out = tx.vout[i];
        ss << "    {\n";
        ss << "      \"value\": " << format_amount(out.amount) << ",\n";
        ss << "      \"n\": " << i << ",\n";
        ss << "      \"pubkey_hash\": \"" << flow::hex_encode(out.pubkey_hash.data(), 32) << "\"\n";
        ss << "    }" << (i + 1 < tx.vout.size() ? "," : "") << "\n";
    }
    ss << "  ]\n";

    ss << "}";
    return ss.str();
}

// ============================================================================
// Command execution
// ============================================================================

static void cmd_add_input(flow::CTransaction& tx, const std::string& arg) {
    // arg = TXID:VOUT
    auto colon = arg.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon == arg.size() - 1) {
        std::cerr << "error: in= requires TXID:VOUT format" << std::endl;
        std::exit(1);
    }

    std::string txid_hex = arg.substr(0, colon);
    std::string vout_str = arg.substr(colon + 1);

    flow::CTxIn input;
    input.prevout.txid = decode_txid(txid_hex);
    try {
        input.prevout.index = static_cast<uint32_t>(std::stoul(vout_str));
    } catch (...) {
        std::cerr << "error: invalid VOUT index '" << vout_str << "'" << std::endl;
        std::exit(1);
    }

    tx.vin.push_back(input);
}

static void cmd_add_output(flow::CTransaction& tx, const std::string& arg) {
    // arg = VALUE:ADDRESS
    auto colon = arg.find(':');
    if (colon == std::string::npos) {
        std::cerr << "error: outaddr= requires VALUE:ADDRESS format" << std::endl;
        std::exit(1);
    }

    std::string value_str = arg.substr(0, colon);
    std::string address = arg.substr(colon + 1);

    int64_t amount = parse_amount(value_str);
    if (amount <= 0) {
        std::cerr << "error: output amount must be positive" << std::endl;
        std::exit(1);
    }

    // Decode the Bech32m address to get the pubkey hash
    flow::Bech32mDecoded decoded = flow::bech32m_decode(address);
    if (!decoded.valid) {
        std::cerr << "error: invalid address '" << address << "'" << std::endl;
        std::exit(1);
    }

    if (decoded.program.size() != 20) {
        std::cerr << "error: address program must be 20 bytes (got "
                  << decoded.program.size() << ")" << std::endl;
        std::exit(1);
    }

    flow::CTxOut output;
    output.amount = amount;
    // Zero-fill the 32-byte pubkey_hash, then copy the 20-byte program
    output.pubkey_hash = {};
    std::memcpy(output.pubkey_hash.data(), decoded.program.data(), 20);

    tx.vout.push_back(output);
}

static void cmd_add_data_output(flow::CTransaction& tx, const std::string& arg) {
    // arg = hex data
    std::vector<uint8_t> data = flow::hex_decode(arg);
    if (data.empty()) {
        std::cerr << "error: outdata= requires valid hex data" << std::endl;
        std::exit(1);
    }

    // OP_RETURN output: amount = 0, pubkey_hash = first 32 bytes of keccak256(data)
    flow::CTxOut output;
    output.amount = 0;
    flow::uint256 hash = flow::keccak256(data.data(), data.size());
    std::memcpy(output.pubkey_hash.data(), hash.data(), 32);

    tx.vout.push_back(output);
}

static void cmd_sign(flow::CTransaction& tx, const std::string& arg) {
    // arg = PRIVKEY or PRIVKEY:INPUT_INDEX
    std::string privkey_hex;
    int input_index = -1;  // -1 = sign all

    auto colon = arg.find(':');
    if (colon != std::string::npos) {
        privkey_hex = arg.substr(0, colon);
        try {
            input_index = std::stoi(arg.substr(colon + 1));
        } catch (...) {
            std::cerr << "error: invalid input index in sign command" << std::endl;
            std::exit(1);
        }
    } else {
        privkey_hex = arg;
    }

    // Decode private key
    std::vector<uint8_t> privkey_bytes = flow::hex_decode(privkey_hex);
    if (privkey_bytes.size() != 32) {
        std::cerr << "error: private key must be 32 bytes (64 hex chars), got "
                  << privkey_bytes.size() << " bytes" << std::endl;
        std::exit(1);
    }

    // Derive public key
    std::array<uint8_t, 32> pubkey = flow::derive_pubkey(privkey_bytes.data());

    // Get the signing hash (serialized tx without signatures)
    std::vector<uint8_t> tx_hash_data = tx.serialize_for_hash();
    flow::uint256 tx_hash = flow::keccak256(tx_hash_data.data(), tx_hash_data.size());

    // Sign the specified input(s)
    if (input_index >= 0) {
        if (static_cast<size_t>(input_index) >= tx.vin.size()) {
            std::cerr << "error: input index " << input_index
                      << " out of range (tx has " << tx.vin.size()
                      << " inputs)" << std::endl;
            std::exit(1);
        }
        auto sig = flow::ed25519_sign(
            tx_hash.data(), 32,
            privkey_bytes.data(), pubkey.data());
        tx.vin[static_cast<size_t>(input_index)].signature = sig;
        tx.vin[static_cast<size_t>(input_index)].pubkey = pubkey;
    } else {
        // Sign all inputs
        for (auto& input : tx.vin) {
            if (input.is_coinbase()) continue;
            auto sig = flow::ed25519_sign(
                tx_hash.data(), 32,
                privkey_bytes.data(), pubkey.data());
            input.signature = sig;
            input.pubkey = pubkey;
        }
    }
}

static void cmd_set(flow::CTransaction& tx, const std::string& arg) {
    auto colon = arg.find(':');
    if (colon == std::string::npos) {
        std::cerr << "error: set= requires NAME:VALUE format" << std::endl;
        std::exit(1);
    }

    std::string name = arg.substr(0, colon);
    std::string value = arg.substr(colon + 1);

    if (name == "version") {
        try { tx.version = static_cast<uint32_t>(std::stoul(value)); } catch (...) {
            std::cerr << "error: invalid version value '" << value << "'" << std::endl;
            std::exit(1);
        }
    } else if (name == "locktime") {
        try { tx.locktime = std::stoll(value); } catch (...) {
            std::cerr << "error: invalid locktime value '" << value << "'" << std::endl;
            std::exit(1);
        }
    } else {
        std::cerr << "error: unknown set field '" << name
                  << "' (expected: version, locktime)" << std::endl;
        std::exit(1);
    }
}

static void cmd_del_input(flow::CTransaction& tx, const std::string& arg) {
    size_t index;
    try { index = std::stoul(arg); } catch (...) {
        std::cerr << "error: invalid input index '" << arg << "'" << std::endl;
        std::exit(1);
    }
    if (index >= tx.vin.size()) {
        std::cerr << "error: input index " << index << " out of range (tx has "
                  << tx.vin.size() << " inputs)" << std::endl;
        std::exit(1);
    }
    tx.vin.erase(tx.vin.begin() + static_cast<ptrdiff_t>(index));
}

static void cmd_del_output(flow::CTransaction& tx, const std::string& arg) {
    size_t index;
    try { index = std::stoul(arg); } catch (...) {
        std::cerr << "error: invalid output index '" << arg << "'" << std::endl;
        std::exit(1);
    }
    if (index >= tx.vout.size()) {
        std::cerr << "error: output index " << index << " out of range (tx has "
                  << tx.vout.size() << " outputs)" << std::endl;
        std::exit(1);
    }
    tx.vout.erase(tx.vout.begin() + static_cast<ptrdiff_t>(index));
}

// ============================================================================
// Usage
// ============================================================================

static void print_usage() {
    std::cout << CLIENT_NAME << " Transaction Utility v" << CLIENT_VERSION_STRING << "\n\n";
    std::cout << "Usage:\n";
    std::cout << "  flowcoin-tx -create [commands...]\n";
    std::cout << "  flowcoin-tx <hex-tx> [commands...]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  in=TXID:VOUT              Add input\n";
    std::cout << "  outaddr=VALUE:ADDRESS      Add output (VALUE in FLOW)\n";
    std::cout << "  outdata=HEX               Add data output (OP_RETURN)\n";
    std::cout << "  sign=PRIVKEY[:INPUT]       Sign with Ed25519 key (hex)\n";
    std::cout << "  set=version:N             Set transaction version\n";
    std::cout << "  set=locktime:N            Set locktime\n";
    std::cout << "  delin=N                   Delete input at index N\n";
    std::cout << "  delout=N                  Delete output at index N\n\n";
    std::cout << "Options:\n";
    std::cout << "  -create                   Create a new empty transaction\n";
    std::cout << "  -json                     Output as JSON instead of hex\n";
    std::cout << "  -txid                     Output only the transaction ID\n";
    std::cout << "  --help, -h                Print this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  flowcoin-tx -create in=abc...def:0 outaddr=10.0:fl1q... sign=<privkey-hex>\n";
    std::cout << "  flowcoin-tx <hex> sign=abc...def\n";
    std::cout << "  flowcoin-tx -create -json in=abc...def:0 outaddr=50.0:fl1q...\n";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    bool create_new = false;
    bool output_json = false;
    bool output_txid = false;
    std::string input_hex;
    std::vector<std::string> commands;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        if (a == "--help" || a == "-h" || a == "-?") {
            print_usage();
            return 0;
        }
        if (a == "-create") {
            create_new = true;
            continue;
        }
        if (a == "-json") {
            output_json = true;
            continue;
        }
        if (a == "-txid") {
            output_txid = true;
            continue;
        }

        // Check if this is a command (contains '=')
        if (starts_with(a, "in=") || starts_with(a, "outaddr=") ||
            starts_with(a, "outdata=") || starts_with(a, "sign=") ||
            starts_with(a, "set=") || starts_with(a, "delin=") ||
            starts_with(a, "delout=")) {
            commands.push_back(a);
            continue;
        }

        // First non-option, non-command argument is the input hex
        if (input_hex.empty() && !create_new) {
            input_hex = a;
        } else {
            std::cerr << "error: unexpected argument '" << a << "'" << std::endl;
            return 1;
        }
    }

    // Create or deserialize the transaction
    flow::CTransaction tx;

    if (create_new) {
        tx.version = 1;
        tx.locktime = 0;
    } else if (!input_hex.empty()) {
        std::vector<uint8_t> raw = flow::hex_decode(input_hex);
        if (raw.empty()) {
            std::cerr << "error: invalid hex input" << std::endl;
            return 1;
        }
        if (!deserialize_tx(raw, tx)) {
            std::cerr << "error: failed to deserialize transaction" << std::endl;
            return 1;
        }
    } else {
        std::cerr << "error: specify -create or provide a hex-encoded transaction" << std::endl;
        return 1;
    }

    // Execute commands in order
    for (const auto& cmd : commands) {
        auto eq = cmd.find('=');
        std::string verb = cmd.substr(0, eq);
        std::string arg = (eq != std::string::npos) ? cmd.substr(eq + 1) : "";

        if (verb == "in") {
            cmd_add_input(tx, arg);
        } else if (verb == "outaddr") {
            cmd_add_output(tx, arg);
        } else if (verb == "outdata") {
            cmd_add_data_output(tx, arg);
        } else if (verb == "sign") {
            cmd_sign(tx, arg);
        } else if (verb == "set") {
            cmd_set(tx, arg);
        } else if (verb == "delin") {
            cmd_del_input(tx, arg);
        } else if (verb == "delout") {
            cmd_del_output(tx, arg);
        }
    }

    // Output the result
    if (output_txid) {
        // Print just the transaction ID
        std::cout << encode_txid(tx.get_txid()) << std::endl;
    } else if (output_json) {
        // Print JSON representation
        std::cout << tx_to_json(tx) << std::endl;
    } else {
        // Print raw hex
        std::vector<uint8_t> raw = serialize_tx(tx);
        std::cout << flow::hex_encode(raw) << std::endl;
    }

    return 0;
}
