// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "config.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <string>

namespace flow {

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool Config::load(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return false;

    std::string line;
    while (std::getline(ifs, line)) {
        line = trim(line);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));

        if (!key.empty()) {
            values_[key] = val;
        }
    }

    return true;
}

std::string Config::get(const std::string& key, const std::string& default_val) const {
    auto it = values_.find(key);
    if (it != values_.end()) return it->second;
    return default_val;
}

int Config::get_int(const std::string& key, int default_val) const {
    auto it = values_.find(key);
    if (it == values_.end()) return default_val;
    try {
        return std::stoi(it->second);
    } catch (...) {
        return default_val;
    }
}

bool Config::get_bool(const std::string& key, bool default_val) const {
    auto it = values_.find(key);
    if (it == values_.end()) return default_val;
    std::string v = it->second;
    std::transform(v.begin(), v.end(), v.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (v == "1" || v == "true" || v == "yes") return true;
    if (v == "0" || v == "false" || v == "no") return false;
    return default_val;
}

bool Config::has(const std::string& key) const {
    return values_.find(key) != values_.end();
}

void Config::set(const std::string& key, const std::string& value) {
    values_[key] = value;
}

} // namespace flow
