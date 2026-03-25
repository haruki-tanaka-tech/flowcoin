// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "common/settings.h"

#include <fstream>
#include <sstream>

namespace flow::common {

// ============================================================================
// File I/O — Simple JSON serialization (no nlohmann dependency)
// ============================================================================

// Minimal JSON writer for settings persistence.
// Format: { "section": { "key": value, ... }, ... }

static std::string escape_json_string(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 2);
    result += '"';
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned>(c));
                    result += buf;
                } else {
                    result += c;
                }
                break;
        }
    }
    result += '"';
    return result;
}

static std::string setting_value_to_json(const SettingValue& val) {
    if (std::holds_alternative<std::monostate>(val)) {
        return "null";
    }
    if (std::holds_alternative<bool>(val)) {
        return std::get<bool>(val) ? "true" : "false";
    }
    if (std::holds_alternative<int64_t>(val)) {
        return std::to_string(std::get<int64_t>(val));
    }
    if (std::holds_alternative<double>(val)) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.17g", std::get<double>(val));
        return buf;
    }
    if (std::holds_alternative<std::string>(val)) {
        return escape_json_string(std::get<std::string>(val));
    }
    if (std::holds_alternative<std::vector<std::string>>(val)) {
        const auto& list = std::get<std::vector<std::string>>(val);
        std::string result = "[";
        for (size_t i = 0; i < list.size(); ++i) {
            if (i > 0) result += ", ";
            result += escape_json_string(list[i]);
        }
        result += "]";
        return result;
    }
    return "null";
}

bool Settings::save(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "{\n";
    bool first_section = true;
    for (const auto& [section, entries] : data_) {
        if (!first_section) file << ",\n";
        first_section = false;

        file << "  " << escape_json_string(section) << ": {\n";
        bool first_entry = true;
        for (const auto& [key, value] : entries) {
            if (!first_entry) file << ",\n";
            first_entry = false;
            file << "    " << escape_json_string(key) << ": "
                 << setting_value_to_json(value);
        }
        file << "\n  }";
    }
    file << "\n}\n";

    return file.good();
}

// Minimal JSON parser for settings loading.
// Only handles the specific format we write (object of objects).

static void skip_whitespace(const std::string& s, size_t& pos) {
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' ||
           s[pos] == '\n' || s[pos] == '\r')) {
        ++pos;
    }
}

static std::string parse_json_string(const std::string& s, size_t& pos) {
    if (pos >= s.size() || s[pos] != '"') return "";
    ++pos;
    std::string result;
    while (pos < s.size() && s[pos] != '"') {
        if (s[pos] == '\\' && pos + 1 < s.size()) {
            ++pos;
            switch (s[pos]) {
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                case 'u': {
                    // Skip \uXXXX for simplicity (treat as literal)
                    result += "\\u";
                    break;
                }
                default: result += s[pos]; break;
            }
        } else {
            result += s[pos];
        }
        ++pos;
    }
    if (pos < s.size()) ++pos; // skip closing quote
    return result;
}

static SettingValue parse_json_value(const std::string& s, size_t& pos) {
    skip_whitespace(s, pos);
    if (pos >= s.size()) return std::monostate{};

    char c = s[pos];

    // String
    if (c == '"') {
        return parse_json_string(s, pos);
    }

    // Array (list of strings)
    if (c == '[') {
        ++pos;
        std::vector<std::string> list;
        skip_whitespace(s, pos);
        while (pos < s.size() && s[pos] != ']') {
            skip_whitespace(s, pos);
            if (s[pos] == '"') {
                list.push_back(parse_json_string(s, pos));
            }
            skip_whitespace(s, pos);
            if (pos < s.size() && s[pos] == ',') ++pos;
        }
        if (pos < s.size()) ++pos; // skip ']'
        return list;
    }

    // true/false
    if (s.substr(pos, 4) == "true") {
        pos += 4;
        return true;
    }
    if (s.substr(pos, 5) == "false") {
        pos += 5;
        return false;
    }

    // null
    if (s.substr(pos, 4) == "null") {
        pos += 4;
        return std::monostate{};
    }

    // Number (int or double)
    size_t start = pos;
    bool is_float = false;
    if (s[pos] == '-') ++pos;
    while (pos < s.size() && ((s[pos] >= '0' && s[pos] <= '9') ||
           s[pos] == '.' || s[pos] == 'e' || s[pos] == 'E' ||
           s[pos] == '+' || s[pos] == '-')) {
        if (s[pos] == '.' || s[pos] == 'e' || s[pos] == 'E') is_float = true;
        ++pos;
    }
    std::string num_str = s.substr(start, pos - start);
    if (is_float) {
        try { return std::stod(num_str); } catch (...) {}
    } else {
        try { return static_cast<int64_t>(std::stoll(num_str)); } catch (...) {}
    }

    return std::monostate{};
}

bool Settings::load(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ifstream file(path);
    if (!file.is_open()) return true; // Missing file is not an error

    std::ostringstream ss;
    ss << file.rdbuf();
    std::string content = ss.str();

    size_t pos = 0;
    skip_whitespace(content, pos);
    if (pos >= content.size() || content[pos] != '{') return false;
    ++pos;

    while (pos < content.size()) {
        skip_whitespace(content, pos);
        if (content[pos] == '}') break;
        if (content[pos] == ',') { ++pos; continue; }

        // Parse section name
        std::string section = parse_json_string(content, pos);
        skip_whitespace(content, pos);
        if (pos < content.size() && content[pos] == ':') ++pos;
        skip_whitespace(content, pos);

        // Parse section object
        if (pos < content.size() && content[pos] == '{') {
            ++pos;
            while (pos < content.size()) {
                skip_whitespace(content, pos);
                if (content[pos] == '}') { ++pos; break; }
                if (content[pos] == ',') { ++pos; continue; }

                std::string key = parse_json_string(content, pos);
                skip_whitespace(content, pos);
                if (pos < content.size() && content[pos] == ':') ++pos;

                SettingValue value = parse_json_value(content, pos);
                data_[section][key] = value;
            }
        }
    }

    return true;
}

// ============================================================================
// Value access
// ============================================================================

SettingValue Settings::get(const std::string& section,
                            const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto sit = data_.find(section);
    if (sit == data_.end()) return std::monostate{};
    auto kit = sit->second.find(key);
    if (kit == sit->second.end()) return std::monostate{};
    return kit->second;
}

std::string Settings::get_string(const std::string& section,
                                   const std::string& key,
                                   const std::string& default_val) const {
    auto val = get(section, key);
    if (std::holds_alternative<std::string>(val)) {
        return std::get<std::string>(val);
    }
    return default_val;
}

bool Settings::get_bool(const std::string& section,
                          const std::string& key,
                          bool default_val) const {
    auto val = get(section, key);
    if (std::holds_alternative<bool>(val)) {
        return std::get<bool>(val);
    }
    if (std::holds_alternative<int64_t>(val)) {
        return std::get<int64_t>(val) != 0;
    }
    if (std::holds_alternative<std::string>(val)) {
        const auto& s = std::get<std::string>(val);
        if (s == "1" || s == "true" || s == "yes") return true;
        if (s == "0" || s == "false" || s == "no") return false;
    }
    return default_val;
}

int64_t Settings::get_int(const std::string& section,
                            const std::string& key,
                            int64_t default_val) const {
    auto val = get(section, key);
    if (std::holds_alternative<int64_t>(val)) {
        return std::get<int64_t>(val);
    }
    if (std::holds_alternative<double>(val)) {
        return static_cast<int64_t>(std::get<double>(val));
    }
    if (std::holds_alternative<std::string>(val)) {
        try { return std::stoll(std::get<std::string>(val)); } catch (...) {}
    }
    return default_val;
}

double Settings::get_double(const std::string& section,
                              const std::string& key,
                              double default_val) const {
    auto val = get(section, key);
    if (std::holds_alternative<double>(val)) {
        return std::get<double>(val);
    }
    if (std::holds_alternative<int64_t>(val)) {
        return static_cast<double>(std::get<int64_t>(val));
    }
    if (std::holds_alternative<std::string>(val)) {
        try { return std::stod(std::get<std::string>(val)); } catch (...) {}
    }
    return default_val;
}

std::vector<std::string> Settings::get_list(const std::string& section,
                                              const std::string& key) const {
    auto val = get(section, key);
    if (std::holds_alternative<std::vector<std::string>>(val)) {
        return std::get<std::vector<std::string>>(val);
    }
    if (std::holds_alternative<std::string>(val)) {
        return {std::get<std::string>(val)};
    }
    return {};
}

// ============================================================================
// Value modification
// ============================================================================

void Settings::set(const std::string& section,
                    const std::string& key,
                    const SettingValue& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    data_[section][key] = value;
}

bool Settings::remove(const std::string& section, const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto sit = data_.find(section);
    if (sit == data_.end()) return false;
    auto kit = sit->second.find(key);
    if (kit == sit->second.end()) return false;
    sit->second.erase(kit);
    if (sit->second.empty()) {
        data_.erase(sit);
    }
    return true;
}

bool Settings::has(const std::string& section, const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto sit = data_.find(section);
    if (sit == data_.end()) return false;
    return sit->second.count(key) > 0;
}

void Settings::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    data_.clear();
}

// ============================================================================
// Enumeration
// ============================================================================

std::vector<std::string> Settings::keys(const std::string& section) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    auto sit = data_.find(section);
    if (sit != data_.end()) {
        for (const auto& [key, _] : sit->second) {
            result.push_back(key);
        }
    }
    return result;
}

std::vector<std::string> Settings::sections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [section, _] : data_) {
        result.push_back(section);
    }
    return result;
}

// ============================================================================
// Global instance
// ============================================================================

Settings& Settings::instance() {
    static Settings inst;
    return inst;
}

} // namespace flow::common
