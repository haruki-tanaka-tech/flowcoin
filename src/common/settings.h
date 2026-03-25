// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Settings: persistent runtime settings that can be modified via RPC
// and saved to settings.json. Separate from the config file (flowcoin.conf)
// which is read-only at runtime.
//
// Examples of persistent settings:
//   - Wallet-specific preferences
//   - Manually banned peers
//   - Fee rate overrides
//   - Debug categories

#ifndef FLOWCOIN_COMMON_SETTINGS_H
#define FLOWCOIN_COMMON_SETTINGS_H

#include <map>
#include <mutex>
#include <string>
#include <variant>
#include <vector>

namespace flow::common {

// ============================================================================
// Setting value type
// ============================================================================

using SettingValue = std::variant<
    std::monostate,          // null / unset
    bool,                    // boolean flag
    int64_t,                 // integer value
    double,                  // floating-point value
    std::string,             // string value
    std::vector<std::string> // list of strings
>;

// ============================================================================
// Settings manager
// ============================================================================

class Settings {
public:
    Settings() = default;

    // ---- File I/O ----------------------------------------------------------

    /// Load settings from a JSON file.
    /// Returns false on parse error (file not existing is not an error).
    bool load(const std::string& path);

    /// Save current settings to a JSON file.
    /// Creates the file if it doesn't exist, overwrites if it does.
    bool save(const std::string& path) const;

    // ---- Value access ------------------------------------------------------

    /// Get a setting value. Returns monostate if not set.
    SettingValue get(const std::string& section,
                     const std::string& key) const;

    /// Get a string setting with default.
    std::string get_string(const std::string& section,
                            const std::string& key,
                            const std::string& default_val = "") const;

    /// Get a boolean setting with default.
    bool get_bool(const std::string& section,
                   const std::string& key,
                   bool default_val = false) const;

    /// Get an integer setting with default.
    int64_t get_int(const std::string& section,
                     const std::string& key,
                     int64_t default_val = 0) const;

    /// Get a double setting with default.
    double get_double(const std::string& section,
                       const std::string& key,
                       double default_val = 0.0) const;

    /// Get a list setting.
    std::vector<std::string> get_list(const std::string& section,
                                       const std::string& key) const;

    // ---- Value modification ------------------------------------------------

    /// Set a setting value.
    void set(const std::string& section,
             const std::string& key,
             const SettingValue& value);

    /// Remove a setting.
    bool remove(const std::string& section,
                 const std::string& key);

    /// Check if a setting exists.
    bool has(const std::string& section,
              const std::string& key) const;

    /// Clear all settings.
    void clear();

    // ---- Enumeration -------------------------------------------------------

    /// Get all keys in a section.
    std::vector<std::string> keys(const std::string& section) const;

    /// Get all section names.
    std::vector<std::string> sections() const;

    // ---- Global instance ---------------------------------------------------

    static Settings& instance();

private:
    mutable std::mutex mutex_;

    // Nested map: section -> key -> value
    std::map<std::string, std::map<std::string, SettingValue>> data_;

    // Helper: make composite key
    static std::string make_key(const std::string& section,
                                 const std::string& key) {
        return section.empty() ? key : section + "." + key;
    }
};

} // namespace flow::common

#endif // FLOWCOIN_COMMON_SETTINGS_H
