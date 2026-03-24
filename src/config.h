// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Configuration file parser for FlowCoin.
// Parses simple key=value files (flowcoin.conf format).

#ifndef FLOWCOIN_CONFIG_H
#define FLOWCOIN_CONFIG_H

#include <string>
#include <unordered_map>

namespace flow {

class Config {
public:
    /// Load a configuration file. Returns true on success.
    /// Lines starting with '#' are comments. Format: key=value
    bool load(const std::string& path);

    /// Get a string value, returning default_val if key is absent.
    std::string get(const std::string& key, const std::string& default_val = "") const;

    /// Get an integer value, returning default_val if key is absent or not parseable.
    int get_int(const std::string& key, int default_val = 0) const;

    /// Get a boolean value. Recognized truthy: "1", "true", "yes".
    bool get_bool(const std::string& key, bool default_val = false) const;

    /// Check if a key exists.
    bool has(const std::string& key) const;

    /// Set a value programmatically (e.g., from command-line overrides).
    void set(const std::string& key, const std::string& value);

private:
    std::unordered_map<std::string, std::string> values_;
};

} // namespace flow

#endif // FLOWCOIN_CONFIG_H
