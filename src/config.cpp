// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "config.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>

namespace flow {

// ============================================================================
// Utility helpers
// ============================================================================

std::string Config::trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string Config::to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string Config::random_hex(size_t bytes) {
    // Use std::random_device for entropy, not cryptographic but sufficient
    // for cookie auth randomness. In production, this could use OS entropy.
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes * 2);
    for (size_t i = 0; i < bytes; ++i) {
        uint8_t b = static_cast<uint8_t>(dist(gen));
        result.push_back(hex_chars[b >> 4]);
        result.push_back(hex_chars[b & 0x0f]);
    }
    return result;
}

// ============================================================================
// File I/O
// ============================================================================

bool Config::parse_line(const std::string& line, int line_num,
                        const std::string& current_section) {
    std::string trimmed = trim(line);

    // Skip empty lines and comments
    if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
        return true;
    }

    // Section header: [section]
    if (trimmed.front() == '[' && trimmed.back() == ']') {
        // Sections are handled by the caller
        return true;
    }

    // Key=value
    auto eq = trimmed.find('=');
    if (eq == std::string::npos) {
        // Bare key without value: treat as boolean true
        std::string key = trim(trimmed);
        if (!key.empty()) {
            std::string full_key = current_section.empty()
                ? key : current_section + "." + key;
            values_[full_key].push_back("1");
        }
        return true;
    }

    std::string key = trim(trimmed.substr(0, eq));
    std::string val = trim(trimmed.substr(eq + 1));

    if (key.empty()) {
        // Ignore lines with empty keys (malformed)
        (void)line_num;
        return false;
    }

    // Remove surrounding quotes from value if present
    if (val.size() >= 2) {
        if ((val.front() == '"' && val.back() == '"') ||
            (val.front() == '\'' && val.back() == '\'')) {
            val = val.substr(1, val.size() - 2);
        }
    }

    // Apply section prefix
    std::string full_key = current_section.empty()
        ? key : current_section + "." + key;

    values_[full_key].push_back(val);
    return true;
}

bool Config::load(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return false;

    std::string line;
    int line_num = 0;
    std::string current_section;

    while (std::getline(ifs, line)) {
        ++line_num;
        std::string trimmed = trim(line);

        // Check for section header
        if (!trimmed.empty() && trimmed.front() == '[' && trimmed.back() == ']') {
            current_section = trim(trimmed.substr(1, trimmed.size() - 2));
            continue;
        }

        parse_line(line, line_num, current_section);
    }

    return true;
}

bool Config::save(const std::string& path) const {
    // Write to a temporary file first, then rename for atomicity
    std::string tmp_path = path + ".tmp";

    std::ofstream ofs(tmp_path);
    if (!ofs.is_open()) return false;

    ofs << "# FlowCoin configuration file\n";
    ofs << "# Generated automatically — manual edits are preserved on next save\n\n";

    // Group by section
    std::map<std::string, std::vector<std::pair<std::string, std::string>>> sections;

    for (const auto& [key, vals] : values_) {
        auto dot = key.find('.');
        std::string section;
        std::string bare_key;
        if (dot != std::string::npos) {
            section = key.substr(0, dot);
            bare_key = key.substr(dot + 1);
        } else {
            bare_key = key;
        }

        for (const auto& v : vals) {
            sections[section].emplace_back(bare_key, v);
        }
    }

    // Write unsectioned keys first
    auto it = sections.find("");
    if (it != sections.end()) {
        for (const auto& [k, v] : it->second) {
            ofs << k << "=" << v << "\n";
        }
        ofs << "\n";
    }

    // Write sectioned keys
    for (const auto& [section, entries] : sections) {
        if (section.empty()) continue;
        ofs << "[" << section << "]\n";
        for (const auto& [k, v] : entries) {
            ofs << k << "=" << v << "\n";
        }
        ofs << "\n";
    }

    ofs.close();

    // Rename temp file to final path
    try {
        std::filesystem::rename(tmp_path, path);
    } catch (const std::filesystem::filesystem_error&) {
        // Fallback: direct overwrite
        std::ofstream out(path);
        if (!out.is_open()) return false;
        std::ifstream in(tmp_path);
        out << in.rdbuf();
        out.close();
        std::filesystem::remove(tmp_path);
    }

    return true;
}

// ============================================================================
// Typed getters
// ============================================================================

std::string Config::get(const std::string& key,
                        const std::string& default_val) const {
    auto it = values_.find(key);
    if (it != values_.end() && !it->second.empty()) {
        return it->second.back();  // Return the last value (latest wins)
    }
    return default_val;
}

std::string Config::get_string(const std::string& key,
                               const std::string& default_val) const {
    return get(key, default_val);
}

int64_t Config::get_int(const std::string& key, int64_t default_val) const {
    auto it = values_.find(key);
    if (it == values_.end() || it->second.empty()) return default_val;
    try {
        return std::stoll(it->second.back());
    } catch (...) {
        return default_val;
    }
}

bool Config::get_bool(const std::string& key, bool default_val) const {
    auto it = values_.find(key);
    if (it == values_.end() || it->second.empty()) return default_val;
    std::string v = to_lower(it->second.back());
    if (v == "1" || v == "true" || v == "yes") return true;
    if (v == "0" || v == "false" || v == "no") return false;
    return default_val;
}

double Config::get_double(const std::string& key, double default_val) const {
    auto it = values_.find(key);
    if (it == values_.end() || it->second.empty()) return default_val;
    try {
        return std::stod(it->second.back());
    } catch (...) {
        return default_val;
    }
}

std::vector<std::string> Config::get_multi(const std::string& key) const {
    auto it = values_.find(key);
    if (it != values_.end()) return it->second;
    return {};
}

// ============================================================================
// Setters
// ============================================================================

void Config::set(const std::string& key, const std::string& value) {
    values_[key] = {value};  // Replace all previous values
}

void Config::set(const std::string& key, int64_t value) {
    set(key, std::to_string(value));
}

void Config::set(const std::string& key, bool value) {
    set(key, std::string(value ? "1" : "0"));
}

// ============================================================================
// Queries
// ============================================================================

bool Config::has(const std::string& key) const {
    return values_.find(key) != values_.end();
}

std::vector<std::string> Config::keys() const {
    std::vector<std::string> result;
    result.reserve(values_.size());
    for (const auto& [k, _] : values_) {
        result.push_back(k);
    }
    return result;
}

size_t Config::size() const {
    return values_.size();
}

bool Config::remove(const std::string& key) {
    return values_.erase(key) > 0;
}

void Config::clear() {
    values_.clear();
}

// ============================================================================
// RPC authentication
// ============================================================================

std::string Config::get_rpc_user() const {
    return get("rpcuser", "");
}

std::string Config::get_rpc_password() const {
    return get("rpcpassword", "");
}

void Config::generate_cookie(const std::string& datadir) {
    std::string cookie_user = "__cookie__";
    std::string cookie_pass = random_hex(32);  // 64 hex chars = 256 bits

    std::string cookie_file = datadir;
    if (!cookie_file.empty() && cookie_file.back() != '/') {
        cookie_file += "/";
    }
    cookie_file += ".cookie";

    std::ofstream ofs(cookie_file);
    if (ofs.is_open()) {
        ofs << cookie_user << ":" << cookie_pass << "\n";
        ofs.close();

        // Set restrictive permissions (owner-only read/write)
        ::chmod(cookie_file.c_str(), 0600);
    }
}

bool Config::read_cookie(const std::string& datadir,
                         std::string& user, std::string& pass) const {
    std::string cookie_file = datadir;
    if (!cookie_file.empty() && cookie_file.back() != '/') {
        cookie_file += "/";
    }
    cookie_file += ".cookie";

    std::ifstream ifs(cookie_file);
    if (!ifs.is_open()) return false;

    std::string line;
    if (!std::getline(ifs, line)) return false;

    auto colon = line.find(':');
    if (colon == std::string::npos) return false;

    user = line.substr(0, colon);
    pass = line.substr(colon + 1);

    // Trim whitespace from pass
    auto end = pass.find_last_not_of(" \t\r\n");
    if (end != std::string::npos) {
        pass = pass.substr(0, end + 1);
    }

    return !user.empty() && !pass.empty();
}

void Config::remove_cookie(const std::string& datadir) {
    std::string cookie_file = datadir;
    if (!cookie_file.empty() && cookie_file.back() != '/') {
        cookie_file += "/";
    }
    cookie_file += ".cookie";
    std::filesystem::remove(cookie_file);
}

// ============================================================================
// Merge
// ============================================================================

void Config::merge(const Config& other) {
    for (const auto& [key, vals] : other.values_) {
        values_[key] = vals;  // Overwrite
    }
}

void Config::merge_args(const std::vector<std::string>& overrides) {
    for (const auto& arg : overrides) {
        auto eq = arg.find('=');
        if (eq == std::string::npos) {
            // Bare key: treat as boolean true
            values_[arg] = {"1"};
        } else {
            std::string key = arg.substr(0, eq);
            std::string val = arg.substr(eq + 1);
            values_[key] = {val};
        }
    }
}

// ============================================================================
// Debug / Dump
// ============================================================================

std::string Config::dump() const {
    std::ostringstream ss;
    ss << "# Configuration dump (" << values_.size() << " keys)\n";
    for (const auto& [key, vals] : values_) {
        for (const auto& v : vals) {
            ss << key << "=" << v << "\n";
        }
    }
    return ss.str();
}

// ============================================================================
// Network-aware defaults
// ============================================================================

void Config::apply_network_defaults(bool testnet, bool regtest) {
    // Set default ports based on network
    if (testnet) {
        if (!has("port")) set("port", std::string("19333"));
        if (!has("rpcport")) set("rpcport", std::string("19334"));
    } else if (regtest) {
        if (!has("port")) set("port", std::string("29333"));
        if (!has("rpcport")) set("rpcport", std::string("29334"));
    } else {
        if (!has("port")) set("port", std::string("9333"));
        if (!has("rpcport")) set("rpcport", std::string("9334"));
    }

    // Set defaults that aren't network-specific
    if (!has("maxconnections")) set("maxconnections", std::string("125"));
    if (!has("dbcache")) set("dbcache", std::string("450"));
    if (!has("listen")) set("listen", true);
    if (!has("discover")) set("discover", true);
    if (!has("dnsseed")) set("dnsseed", true);
    if (!has("server")) set("server", true);
}

// ============================================================================
// Validation helpers
// ============================================================================

bool Config::validate_port(const std::string& key) const {
    if (!has(key)) return true;
    int64_t val = get_int(key);
    return val >= 0 && val <= 65535;
}

bool Config::validate_positive(const std::string& key) const {
    if (!has(key)) return true;
    return get_int(key) > 0;
}

bool Config::validate_range(const std::string& key, int64_t min_val, int64_t max_val) const {
    if (!has(key)) return true;
    int64_t val = get_int(key);
    return val >= min_val && val <= max_val;
}

std::vector<std::string> Config::validate_all() const {
    std::vector<std::string> errors;

    if (has("port") && !validate_port("port")) {
        errors.push_back("port must be 0-65535");
    }
    if (has("rpcport") && !validate_port("rpcport")) {
        errors.push_back("rpcport must be 0-65535");
    }
    if (has("maxconnections") && !validate_range("maxconnections", 0, 10000)) {
        errors.push_back("maxconnections must be 0-10000");
    }
    if (has("dbcache") && !validate_range("dbcache", 4, 16384)) {
        errors.push_back("dbcache must be 4-16384 MB");
    }
    if (has("par") && !validate_range("par", 0, 256)) {
        errors.push_back("par must be 0-256");
    }
    if (has("prune") && get_int("prune") > 0 && get_int("prune") < 550) {
        errors.push_back("prune target must be >= 550 MB");
    }

    // Check testnet + regtest conflict
    if (get_bool("testnet") && get_bool("regtest")) {
        errors.push_back("cannot use both testnet and regtest");
    }

    // Check port conflicts
    if (has("port") && has("rpcport") && get_int("port") == get_int("rpcport")) {
        errors.push_back("port and rpcport cannot be the same");
    }

    return errors;
}

// ============================================================================
// Environment variable override
// ============================================================================

void Config::apply_env_overrides() {
    // Check for FLOWCOIN_* environment variables
    static const char* env_keys[] = {
        "FLOWCOIN_DATADIR",
        "FLOWCOIN_PORT",
        "FLOWCOIN_RPCPORT",
        "FLOWCOIN_RPCUSER",
        "FLOWCOIN_RPCPASSWORD",
        "FLOWCOIN_TESTNET",
        "FLOWCOIN_REGTEST",
        "FLOWCOIN_DBCACHE",
        "FLOWCOIN_LOGLEVEL",
        nullptr
    };

    static const char* config_keys[] = {
        "datadir",
        "port",
        "rpcport",
        "rpcuser",
        "rpcpassword",
        "testnet",
        "regtest",
        "dbcache",
        "loglevel",
        nullptr
    };

    for (int i = 0; env_keys[i] != nullptr; ++i) {
        const char* val = std::getenv(env_keys[i]);
        if (val && val[0] != '\0') {
            set(config_keys[i], std::string(val));
        }
    }
}

} // namespace flow
