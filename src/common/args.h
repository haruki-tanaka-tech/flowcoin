// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Unified argument and configuration handling.
// Merges command-line arguments with config file settings, where CLI
// arguments take precedence. Supports negation (-nofoo), multi-valued
// arguments (-addnode=X -addnode=Y), sections ([test] in config file),
// and automatic help text generation.
//
// Design follows Bitcoin Core's ArgsManager pattern:
//   1. Register allowed arguments with add_arg()
//   2. Parse CLI with parse_command_line()
//   3. Read config with read_config_file()
//   4. Query values with get_arg() / get_int_arg() / get_bool_arg()

#ifndef FLOWCOIN_COMMON_ARGS_H
#define FLOWCOIN_COMMON_ARGS_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace flow::common {

// ============================================================================
// Argument definition (for registration and help text)
// ============================================================================

struct ArgDef {
    std::string name;         // e.g., "-datadir"
    std::string help;         // Help text
    std::string category;     // Grouping for help output
    bool has_value = true;    // false for boolean flags
    std::string default_val;  // Default value string (for help text)
    bool hidden = false;      // Hidden from normal help output
    bool network_only = false; // Only valid in network section
};

// ============================================================================
// ArgsManager
// ============================================================================

class ArgsManager {
public:
    ArgsManager() = default;

    // ---- Parsing -----------------------------------------------------------

    /// Parse command-line arguments. Returns false on error.
    /// Populates error_message on failure.
    bool parse_command_line(int argc, char* argv[]);

    /// Read a config file (INI-style with [sections]).
    /// Returns false on I/O error.
    bool read_config_file(const std::string& path);

    /// Parse a single line from a config file.
    /// Used internally by read_config_file() and for testing.
    bool parse_config_line(const std::string& line,
                           const std::string& section = "");

    // ---- Value access (CLI overrides config) --------------------------------

    /// Get a string argument value. Returns default_val if not set.
    std::string get_arg(const std::string& name,
                        const std::string& default_val = "") const;

    /// Get an integer argument value.
    int64_t get_int_arg(const std::string& name,
                         int64_t default_val = 0) const;

    /// Get a boolean argument value.
    /// Recognizes: "1", "true", "yes" as true; "0", "false", "no" as false.
    /// -nofoo sets -foo to false.
    bool get_bool_arg(const std::string& name,
                       bool default_val = false) const;

    /// Get a double argument value.
    double get_double_arg(const std::string& name,
                           double default_val = 0.0) const;

    /// Get all values for a multi-valued argument (e.g., -addnode).
    std::vector<std::string> get_multi_arg(const std::string& name) const;

    /// Check if an argument was explicitly set (CLI or config).
    bool is_arg_set(const std::string& name) const;

    /// Check if an argument was negated (-nofoo).
    bool is_arg_negated(const std::string& name) const;

    // ---- Registration -------------------------------------------------------

    /// Register an allowed argument for validation and help text.
    void add_arg(const ArgDef& def);

    /// Check if an argument name is registered.
    bool is_registered(const std::string& name) const;

    /// Generate formatted help text from registered arguments.
    std::string get_help_text() const;

    // ---- Convenience accessors ----------------------------------------------

    /// Get the data directory path.
    /// Priority: -datadir CLI > config > default (~/.flowcoin)
    std::string get_data_dir() const;

    /// Get the selected network name ("mainnet", "testnet", "regtest").
    std::string get_network() const;

    /// Get the config file path (relative to data dir unless absolute).
    std::string get_config_path() const;

    /// Get the command (first non-option argument), if any.
    std::string get_command() const;

    /// Get positional arguments (after the command).
    std::vector<std::string> get_positional_args() const;

    // ---- Programmatic setting (for testing) ---------------------------------

    /// Set an argument value programmatically.
    void set_arg(const std::string& name, const std::string& value);

    /// Clear all parsed arguments (for testing).
    void clear();

    /// Get the last error message from parsing.
    std::string get_error() const;

    // ---- Global instance ----------------------------------------------------

    static ArgsManager& instance();

private:
    mutable std::mutex mutex_;

    // Parsed values: name -> list of values
    std::map<std::string, std::vector<std::string>> cli_args_;
    std::map<std::string, std::vector<std::string>> config_args_;

    // Negated arguments
    std::map<std::string, bool> negated_;

    // Registered argument definitions
    std::vector<ArgDef> registered_args_;

    // The command (e.g., "help", "version")
    std::string command_;

    // Positional arguments after the command
    std::vector<std::string> positional_args_;

    // Last error message
    std::string error_;

    // Internal: get the raw value with priority (CLI > config)
    std::string get_value(const std::string& name) const;

    // Internal: normalize argument name (strip leading -)
    static std::string normalize(const std::string& name);

    // Internal: check for negation prefix
    static bool has_negation_prefix(const std::string& name);
    static std::string strip_negation(const std::string& name);
};

} // namespace flow::common

#endif // FLOWCOIN_COMMON_ARGS_H
