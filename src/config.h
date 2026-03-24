// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Configuration file parser for FlowCoin.
// Parses flowcoin.conf files (key=value with sections, comments, multi-values).
// Supports runtime modification, save-back, RPC cookie auth, and type-safe
// getters with defaults.

#ifndef FLOWCOIN_CONFIG_H
#define FLOWCOIN_CONFIG_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace flow {

// ============================================================================
// Default configuration values
// ============================================================================

namespace defaults {

    constexpr int         MAX_CONNECTIONS     = 125;
    constexpr int         DB_CACHE_MB         = 450;
    constexpr int         RPC_THREADS         = 4;
    constexpr bool        LISTEN              = true;
    constexpr bool        DISCOVER            = true;
    constexpr bool        DNS_SEED            = true;
    constexpr bool        SERVER              = true;
    constexpr int         MAX_UPLOAD_TARGET   = 0;    // unlimited
    constexpr int64_t     MAX_MEMPOOL_SIZE    = 300 * 1024 * 1024;  // 300 MB
    constexpr int64_t     MIN_RELAY_TX_FEE    = 1000; // atomic units per kB
    constexpr int         PAR_THREADS         = 0;    // 0 = auto-detect
    constexpr int64_t     PRUNE_TARGET_MB     = 0;    // 0 = disabled

    constexpr const char* DEFAULT_DATADIR     = ".flowcoin";
    constexpr const char* DEFAULT_CONF_FILE   = "flowcoin.conf";
    constexpr const char* DEFAULT_LOG_FILE    = "debug.log";
    constexpr const char* DEFAULT_WALLET_FILE = "wallet.dat";

    constexpr const char* DEFAULT_RPC_BIND    = "127.0.0.1";
    constexpr const char* DEFAULT_BIND        = "0.0.0.0";

    constexpr const char* DEFAULT_LOG_LEVEL   = "info";

} // namespace defaults

// ============================================================================
// Config class
// ============================================================================

class Config {
public:
    Config() = default;

    // -- File I/O -------------------------------------------------------------

    /// Load a configuration file. Returns true on success.
    /// Lines starting with '#' or ';' are comments. Format: key=value
    /// Multi-value keys (e.g., addnode) are accumulated into a list.
    /// Supports [section] headers: keys under a section become section.key.
    bool load(const std::string& path);

    /// Save the current configuration to a file. Returns true on success.
    /// Writes all keys in sorted order, one per line.
    bool save(const std::string& path) const;

    // -- Typed getters with defaults ------------------------------------------

    /// Get a string value, returning default_val if key is absent.
    std::string get(const std::string& key,
                    const std::string& default_val = "") const;

    /// Alias for get() — used where the string nature is explicit.
    std::string get_string(const std::string& key,
                           const std::string& default_val = "") const;

    /// Get an integer value, returning default_val if key is absent or invalid.
    int64_t get_int(const std::string& key, int64_t default_val = 0) const;

    /// Get a boolean value. Truthy: "1", "true", "yes". Falsy: "0", "false", "no".
    bool get_bool(const std::string& key, bool default_val = false) const;

    /// Get a double value, returning default_val if key is absent or invalid.
    double get_double(const std::string& key, double default_val = 0.0) const;

    /// Get all values for a multi-value key (e.g., addnode entries).
    std::vector<std::string> get_multi(const std::string& key) const;

    // -- Setters --------------------------------------------------------------

    /// Set a string value, replacing any existing value.
    void set(const std::string& key, const std::string& value);

    /// Set an integer value.
    void set(const std::string& key, int64_t value);

    /// Set a boolean value ("1" / "0").
    void set(const std::string& key, bool value);

    // -- Queries --------------------------------------------------------------

    /// Check if a key exists in the configuration.
    bool has(const std::string& key) const;

    /// Get all configuration keys (sorted).
    std::vector<std::string> keys() const;

    /// Get the number of configuration entries.
    size_t size() const;

    /// Remove a key from the configuration. Returns true if the key existed.
    bool remove(const std::string& key);

    /// Clear all configuration entries.
    void clear();

    // -- RPC authentication ---------------------------------------------------

    /// Get the configured RPC username (from rpcuser key).
    std::string get_rpc_user() const;

    /// Get the configured RPC password (from rpcpassword key).
    std::string get_rpc_password() const;

    /// Generate a random .cookie file in the given data directory.
    /// The cookie contains "__cookie__:random_hex" for automatic auth.
    void generate_cookie(const std::string& datadir);

    /// Read an existing .cookie file. Returns true on success.
    bool read_cookie(const std::string& datadir,
                     std::string& user, std::string& pass) const;

    /// Delete the .cookie file in the given data directory.
    static void remove_cookie(const std::string& datadir);

    // -- Merge ----------------------------------------------------------------

    /// Merge another config into this one. Existing keys are overwritten.
    void merge(const Config& other);

    /// Merge command-line overrides. Format: key=value pairs.
    void merge_args(const std::vector<std::string>& overrides);

    // -- Debug / dump ---------------------------------------------------------

    /// Dump all config entries as a formatted string.
    std::string dump() const;

    // -- Network-aware defaults -----------------------------------------------

    /// Apply default values appropriate for the selected network.
    void apply_network_defaults(bool testnet, bool regtest);

    // -- Validation -----------------------------------------------------------

    /// Validate a port key (0-65535).
    bool validate_port(const std::string& key) const;

    /// Validate a key has a positive integer value.
    bool validate_positive(const std::string& key) const;

    /// Validate a key falls within a range.
    bool validate_range(const std::string& key, int64_t min_val, int64_t max_val) const;

    /// Run all validation checks. Returns a list of error messages (empty = all ok).
    std::vector<std::string> validate_all() const;

    // -- Environment variable overrides ---------------------------------------

    /// Apply overrides from FLOWCOIN_* environment variables.
    void apply_env_overrides();

private:
    // Multi-map to support multi-value keys (addnode, debug, etc.)
    std::map<std::string, std::vector<std::string>> values_;

    /// Parse a single line of the config file.
    /// Returns false if the line has a syntax error (logged but not fatal).
    bool parse_line(const std::string& line, int line_num,
                    const std::string& current_section);

    /// Trim whitespace from both ends of a string.
    static std::string trim(const std::string& s);

    /// Convert a string to lowercase.
    static std::string to_lower(const std::string& s);

    /// Generate random hex bytes for cookie auth.
    static std::string random_hex(size_t bytes);
};

} // namespace flow

#endif // FLOWCOIN_CONFIG_H
