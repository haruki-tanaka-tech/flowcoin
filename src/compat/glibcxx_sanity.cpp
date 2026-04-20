// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Verify that the C++ standard library works correctly at startup.
// This catches ABI incompatibilities early (e.g., building with one
// libstdc++ version but linking against another). If any test fails,
// the node should refuse to start rather than produce undefined behavior
// that could lead to consensus divergence or data corruption.

#include "compat/compat.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace flow::compat {

// ============================================================================
// Individual sanity checks
// ============================================================================

static bool test_string_operations() {
    // Basic construction and comparison
    std::string s1 = "FlowCoin";
    std::string s2 = "Flow";
    s2 += "Coin";
    if (s1 != s2) return false;

    // Substring
    if (s1.substr(0, 4) != "Flow") return false;
    if (s1.substr(4) != "Coin") return false;

    // Find
    if (s1.find("Coin") != 4) return false;
    if (s1.find("xyz") != std::string::npos) return false;

    // Empty string
    std::string empty;
    if (!empty.empty()) return false;
    if (empty.size() != 0) return false;

    // Copy semantics
    std::string s3 = s1;
    if (s3 != s1) return false;
    s3[0] = 'X';
    if (s3 == s1) return false;  // Must be independent copies

    // Move semantics
    std::string s4 = "temporary";
    std::string s5 = std::move(s4);
    if (s5 != "temporary") return false;

    // Long string (triggers heap allocation in most implementations)
    std::string long_str(1024, 'A');
    if (long_str.size() != 1024) return false;
    if (long_str[0] != 'A' || long_str[1023] != 'A') return false;

    return true;
}

static bool test_vector_operations() {
    // Basic push_back and size
    std::vector<int> v;
    for (int i = 0; i < 100; ++i) {
        v.push_back(i);
    }
    if (v.size() != 100) return false;
    if (v[0] != 0 || v[99] != 99) return false;

    // Reserve and capacity
    std::vector<int> v2;
    v2.reserve(256);
    if (v2.capacity() < 256) return false;
    if (!v2.empty()) return false;

    // Resize with value
    v2.resize(50, 42);
    if (v2.size() != 50) return false;
    if (v2[0] != 42 || v2[49] != 42) return false;

    // Copy semantics
    std::vector<int> v3 = v;
    if (v3.size() != v.size()) return false;
    v3[0] = 999;
    if (v[0] == 999) return false;  // Original must not be modified

    // Erase
    v3.erase(v3.begin());
    if (v3.size() != 99) return false;
    if (v3[0] != 1) return false;

    // Nested vectors (exercises allocator interaction)
    std::vector<std::vector<int>> nested;
    nested.push_back({1, 2, 3});
    nested.push_back({4, 5, 6});
    if (nested[0][2] != 3) return false;
    if (nested[1][0] != 4) return false;

    return true;
}

static bool test_map_operations() {
    std::map<std::string, int> m;
    m["alpha"] = 1;
    m["beta"] = 2;
    m["gamma"] = 3;

    if (m.size() != 3) return false;
    if (m["beta"] != 2) return false;

    // Ordering (map is sorted)
    auto it = m.begin();
    if (it->first != "alpha") return false;
    ++it;
    if (it->first != "beta") return false;
    ++it;
    if (it->first != "gamma") return false;

    // Find
    auto found = m.find("gamma");
    if (found == m.end()) return false;
    if (found->second != 3) return false;

    auto not_found = m.find("delta");
    if (not_found != m.end()) return false;

    // Erase
    m.erase("beta");
    if (m.size() != 2) return false;
    if (m.count("beta") != 0) return false;

    return true;
}

static bool test_set_operations() {
    std::set<int> s;
    for (int i = 10; i >= 1; --i) {
        s.insert(i);
    }
    if (s.size() != 10) return false;

    // Duplicate insertion
    auto [iter, inserted] = s.insert(5);
    if (inserted) return false;  // Already present

    // Ordering
    auto it = s.begin();
    if (*it != 1) return false;
    auto rit = s.rbegin();
    if (*rit != 10) return false;

    return true;
}

static bool test_sort_algorithm() {
    std::vector<int> v = {5, 3, 8, 1, 9, 2, 7, 4, 6, 0};
    std::sort(v.begin(), v.end());

    for (int i = 0; i < 10; ++i) {
        if (v[static_cast<size_t>(i)] != i) return false;
    }

    // Reverse sort
    std::sort(v.begin(), v.end(), std::greater<int>());
    if (v[0] != 9 || v[9] != 0) return false;

    // Stable sort with equal elements
    std::vector<std::pair<int, int>> pairs = {
        {3, 1}, {1, 2}, {3, 3}, {1, 4}, {2, 5}
    };
    std::stable_sort(pairs.begin(), pairs.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });

    // Check stability: equal keys preserve original order
    if (pairs[0].second != 2 || pairs[1].second != 4) return false;  // key=1
    if (pairs[3].second != 1 || pairs[4].second != 3) return false;  // key=3

    return true;
}

static bool test_list_operations() {
    std::list<int> l;
    for (int i = 0; i < 20; ++i) {
        l.push_back(i);
    }
    if (l.size() != 20) return false;
    if (l.front() != 0 || l.back() != 19) return false;

    l.push_front(-1);
    if (l.front() != -1) return false;
    if (l.size() != 21) return false;

    l.pop_back();
    l.pop_front();
    if (l.size() != 19) return false;

    return true;
}

static bool test_math_functions() {
    // Basic operations that must work correctly for consensus
    double a = std::sqrt(2.0);
    if (a < 1.414 || a > 1.415) return false;

    double b = std::log(1.0);
    if (b != 0.0) return false;

    double c = std::exp(0.0);
    if (c != 1.0) return false;

    double d = std::floor(3.7);
    if (d != 3.0) return false;

    double e = std::ceil(3.2);
    if (e != 4.0) return false;

    double f = std::fabs(-5.5);
    if (f != 5.5) return false;

    // NaN/Inf handling
    if (!std::isnan(std::nan(""))) return false;
    if (!std::isinf(1.0 / 0.0)) return false;
    if (std::isfinite(std::nan(""))) return false;
    if (std::isfinite(1.0 / 0.0)) return false;
    if (!std::isfinite(1.0)) return false;

    // Integer math
    if (std::abs(-42) != 42) return false;
    if (std::min(3, 5) != 3) return false;
    if (std::max(3, 5) != 5) return false;

    return true;
}

static bool test_memory_operations() {
    // memcpy / memset / memcmp
    uint8_t src[64];
    uint8_t dst[64];
    for (int i = 0; i < 64; ++i) {
        src[i] = static_cast<uint8_t>(i);
    }
    std::memcpy(dst, src, 64);
    if (std::memcmp(src, dst, 64) != 0) return false;

    std::memset(dst, 0xFF, 32);
    if (dst[0] != 0xFF || dst[31] != 0xFF) return false;
    if (dst[32] != 32) return false;  // Untouched region

    return true;
}

// ============================================================================
// Public entry point
// ============================================================================

bool glibc_sanity_test() {
    if (!test_string_operations()) return false;
    if (!test_vector_operations()) return false;
    if (!test_map_operations()) return false;
    if (!test_set_operations()) return false;
    if (!test_sort_algorithm()) return false;
    if (!test_list_operations()) return false;
    if (!test_math_functions()) return false;
    if (!test_memory_operations()) return false;
    return true;
}

} // namespace flow::compat
