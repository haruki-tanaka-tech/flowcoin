// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "common/args.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace flow::common {

// ============================================================================
// Normalization helpers
// ============================================================================

std::string ArgsManager::normalize(const std::string& name) {
    std::string n = name;
    // Strip leading dashes
    while (!n.empty() && n[0] == '-') {
        n = n.substr(1);
    }
    // Lowercase for case-insensitive matching
    std::transform(n.begin(), n.end(), n.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return n;
}

bool ArgsManager::has_negation_prefix(const std::string& name) {
    std::string n = name;
    while (!n.empty() && n[0] == '-') {
        n = n.substr(1);
    }
    return n.size() > 2 && n.substr(0, 2) == "no";
}

std::string ArgsManager::strip_negation(const std::string& name) {
    std::string n = normalize(name);
    if (n.size() > 2 && n.substr(0, 2) == "no") {
        return n.substr(2);
    }
    return n;
}

// ============================================================================
// Parsing
// ============================================================================

bool ArgsManager::parse_command_line(int argc, char* argv[]) {
    std::lock_guard<std::mutex> lock(mutex_);

    cli_args_.clear();
    negated_.clear();
    command_.clear();
    positional_args_.clear();
    error_.clear();

    bool past_options = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        // "--" separator: everything after is positional
        if (arg == "--") {
            past_options = true;
            continue;
        }

        if (!past_options && !arg.empty() && arg[0] == '-') {
            // Option argument
            std::string key;
            std::string value;
            bool has_value = false;

            auto eq_pos = arg.find('=');
            if (eq_pos != std::string::npos) {
                key = arg.substr(0, eq_pos);
                value = arg.substr(eq_pos + 1);
                has_value = true;
            } else {
                key = arg;
                // Check if next arg is the value (not starting with -)
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    // Peek: only consume if this arg is known to take a value
                    // For simplicity, flags without '=' are treated as boolean
                }
            }

            std::string norm_key = normalize(key);

            // Handle negation: -nofoo sets foo = false
            if (has_negation_prefix(key)) {
                std::string real_key = strip_negation(key);
                negated_[real_key] = true;
                cli_args_[real_key] = {"0"};
                continue;
            }

            if (has_value) {
                cli_args_[norm_key].push_back(value);
            } else {
                // Boolean flag (no value = true)
                cli_args_[norm_key] = {"1"};
            }
        } else {
            // Positional argument
            if (command_.empty() && !past_options) {
                command_ = arg;
            } else {
                positional_args_.push_back(arg);
            }
        }
    }

    return true;
}

bool ArgsManager::read_config_file(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ifstream file(path);
    if (!file.is_open()) {
        error_ = "Cannot open config file: " + path;
        return false;
    }

    std::string line;
    std::string current_section;
    int line_num = 0;

    while (std::getline(file, line)) {
        ++line_num;

        // Trim whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        size_t end = line.find_last_not_of(" \t\r\n");
        if (end != std::string::npos) {
            line = line.substr(0, end + 1);
        }

        // Skip comments
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        // Section header: [section]
        if (line[0] == '[') {
            auto close = line.find(']');
            if (close == std::string::npos) {
                error_ = "Malformed section at line " + std::to_string(line_num);
                return false;
            }
            current_section = line.substr(1, close - 1);
            std::transform(current_section.begin(), current_section.end(),
                           current_section.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            continue;
        }

        // Key = value
        auto eq_pos = line.find('=');
        if (eq_pos == std::string::npos) {
            // Boolean key (no value = true)
            std::string key = normalize(line);
            if (has_negation_prefix(line)) {
                std::string real_key = strip_negation(line);
                if (config_args_.find(real_key) == config_args_.end()) {
                    config_args_[real_key] = {"0"};
                    negated_[real_key] = true;
                }
            } else {
                if (config_args_.find(key) == config_args_.end()) {
                    config_args_[key] = {"1"};
                }
            }
            continue;
        }

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        // Trim key and value
        auto trim = [](std::string& s) {
            size_t start = s.find_first_not_of(" \t");
            if (start == std::string::npos) { s.clear(); return; }
            size_t end = s.find_last_not_of(" \t");
            s = s.substr(start, end - start + 1);
        };
        trim(key);
        trim(value);

        // Remove quotes from value
        if (value.size() >= 2 &&
            ((value.front() == '"' && value.back() == '"') ||
             (value.front() == '\'' && value.back() == '\''))) {
            value = value.substr(1, value.size() - 2);
        }

        std::string norm_key = normalize(key);

        // If in a section, prefix the key (e.g., [test] port -> test.port)
        if (!current_section.empty()) {
            norm_key = current_section + "." + norm_key;
        }

        config_args_[norm_key].push_back(value);
    }

    return true;
}

bool ArgsManager::parse_config_line(const std::string& line,
                                     const std::string& section) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string trimmed = line;
    size_t start = trimmed.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return true;
    trimmed = trimmed.substr(start);
    size_t end = trimmed.find_last_not_of(" \t\r\n");
    if (end != std::string::npos) trimmed = trimmed.substr(0, end + 1);

    if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') return true;

    auto eq_pos = trimmed.find('=');
    if (eq_pos == std::string::npos) {
        std::string key = normalize(trimmed);
        if (!section.empty()) key = section + "." + key;
        config_args_[key] = {"1"};
        return true;
    }

    std::string key = trimmed.substr(0, eq_pos);
    std::string value = trimmed.substr(eq_pos + 1);

    // Trim
    while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value = value.substr(1);

    std::string norm_key = normalize(key);
    if (!section.empty()) norm_key = section + "." + norm_key;

    config_args_[norm_key].push_back(value);
    return true;
}

// ============================================================================
// Value access
// ============================================================================

std::string ArgsManager::get_value(const std::string& name) const {
    std::string key = normalize(name);

    // CLI takes priority
    auto cit = cli_args_.find(key);
    if (cit != cli_args_.end() && !cit->second.empty()) {
        return cit->second.back();
    }

    // Then config (check network-prefixed first, then plain)
    std::string network = "";
    auto net_it = cli_args_.find("testnet");
    if (net_it != cli_args_.end() && !net_it->second.empty() &&
        net_it->second.back() == "1") {
        network = "test";
    }
    auto reg_it = cli_args_.find("regtest");
    if (reg_it != cli_args_.end() && !reg_it->second.empty() &&
        reg_it->second.back() == "1") {
        network = "regtest";
    }

    if (!network.empty()) {
        auto nit = config_args_.find(network + "." + key);
        if (nit != config_args_.end() && !nit->second.empty()) {
            return nit->second.back();
        }
    }

    auto fit = config_args_.find(key);
    if (fit != config_args_.end() && !fit->second.empty()) {
        return fit->second.back();
    }

    return "";
}

std::string ArgsManager::get_arg(const std::string& name,
                                  const std::string& default_val) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string val = get_value(name);
    return val.empty() ? default_val : val;
}

int64_t ArgsManager::get_int_arg(const std::string& name,
                                   int64_t default_val) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string val = get_value(name);
    if (val.empty()) return default_val;

    try {
        return std::stoll(val);
    } catch (...) {
        return default_val;
    }
}

bool ArgsManager::get_bool_arg(const std::string& name,
                                 bool default_val) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string key = normalize(name);

    // Check negation first
    auto neg_it = negated_.find(key);
    if (neg_it != negated_.end() && neg_it->second) {
        return false;
    }

    std::string val = get_value(name);
    if (val.empty()) return default_val;

    // Parse boolean values
    if (val == "1" || val == "true" || val == "yes" || val == "on") return true;
    if (val == "0" || val == "false" || val == "no" || val == "off") return false;

    return default_val;
}

double ArgsManager::get_double_arg(const std::string& name,
                                     double default_val) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string val = get_value(name);
    if (val.empty()) return default_val;

    try {
        return std::stod(val);
    } catch (...) {
        return default_val;
    }
}

std::vector<std::string> ArgsManager::get_multi_arg(
    const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = normalize(name);

    std::vector<std::string> result;

    // CLI values first
    auto cit = cli_args_.find(key);
    if (cit != cli_args_.end()) {
        result.insert(result.end(), cit->second.begin(), cit->second.end());
    }

    // Config values
    auto fit = config_args_.find(key);
    if (fit != config_args_.end()) {
        result.insert(result.end(), fit->second.begin(), fit->second.end());
    }

    return result;
}

bool ArgsManager::is_arg_set(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = normalize(name);
    return cli_args_.count(key) > 0 || config_args_.count(key) > 0;
}

bool ArgsManager::is_arg_negated(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = normalize(name);
    auto it = negated_.find(key);
    return it != negated_.end() && it->second;
}

// ============================================================================
// Registration and help
// ============================================================================

void ArgsManager::add_arg(const ArgDef& def) {
    std::lock_guard<std::mutex> lock(mutex_);
    registered_args_.push_back(def);
}

bool ArgsManager::is_registered(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = normalize(name);
    for (const auto& def : registered_args_) {
        if (normalize(def.name) == key) return true;
    }
    return false;
}

std::string ArgsManager::get_help_text() const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Group by category
    std::map<std::string, std::vector<const ArgDef*>> by_category;
    for (const auto& def : registered_args_) {
        if (def.hidden) continue;
        by_category[def.category].push_back(&def);
    }

    std::ostringstream ss;

    for (const auto& [cat, defs] : by_category) {
        if (!cat.empty()) {
            ss << "\n" << cat << ":\n";
        }

        for (const auto* def : defs) {
            ss << "  " << def->name;
            if (def->has_value) {
                ss << "=<value>";
            }
            ss << "\n";

            // Wrap help text at ~70 chars with indent
            std::string help = def->help;
            if (!def->default_val.empty()) {
                help += " (default: " + def->default_val + ")";
            }

            // Simple word-wrap
            size_t col = 0;
            size_t max_col = 68;
            std::istringstream words(help);
            std::string word;
            ss << "       ";
            col = 7;
            while (words >> word) {
                if (col + word.size() + 1 > max_col && col > 7) {
                    ss << "\n       ";
                    col = 7;
                }
                ss << " " << word;
                col += word.size() + 1;
            }
            ss << "\n\n";
        }
    }

    return ss.str();
}

// ============================================================================
// Convenience accessors
// ============================================================================

std::string ArgsManager::get_data_dir() const {
    std::string dir = get_arg("datadir", "");
    if (!dir.empty()) return dir;

    // Default: ~/.flowcoin
    const char* home = std::getenv("HOME");
    if (!home) home = std::getenv("USERPROFILE");
    if (!home) return ".flowcoin";

    return std::string(home) + "/.flowcoin";
}

std::string ArgsManager::get_network() const {
    if (get_bool_arg("regtest", false)) return "regtest";
    if (get_bool_arg("testnet", false)) return "testnet";
    return "mainnet";
}

std::string ArgsManager::get_config_path() const {
    std::string conf = get_arg("conf", "flowcoin.conf");
    // If absolute, use as-is
    if (!conf.empty() && conf[0] == '/') return conf;
#ifdef _WIN32
    if (conf.size() >= 2 && conf[1] == ':') return conf;
#endif
    // Relative to data dir
    return get_data_dir() + "/" + conf;
}

std::string ArgsManager::get_command() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return command_;
}

std::vector<std::string> ArgsManager::get_positional_args() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return positional_args_;
}

// ============================================================================
// Programmatic setting
// ============================================================================

void ArgsManager::set_arg(const std::string& name, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = normalize(name);
    cli_args_[key] = {value};
}

void ArgsManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cli_args_.clear();
    config_args_.clear();
    negated_.clear();
    command_.clear();
    positional_args_.clear();
    error_.clear();
    // Keep registered_args_ — definitions survive clear
}

std::string ArgsManager::get_error() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return error_;
}

// ============================================================================
// Global instance
// ============================================================================

ArgsManager& ArgsManager::instance() {
    static ArgsManager mgr;
    return mgr;
}

} // namespace flow::common
