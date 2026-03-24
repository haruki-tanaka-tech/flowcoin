// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.

#include "merkle.h"
#include "keccak.h"

#include <cstring>

namespace flow {

uint256 compute_merkle_root(const std::vector<uint256>& leaves) {
    if (leaves.empty()) {
        return uint256();  // all zeros
    }

    // Working copy — we reduce in-place each round
    std::vector<uint256> level = leaves;

    while (level.size() > 1) {
        // If odd number of entries, duplicate the last one
        if (level.size() % 2 != 0) {
            level.push_back(level.back());
        }

        std::vector<uint256> next;
        next.reserve(level.size() / 2);

        for (size_t i = 0; i < level.size(); i += 2) {
            // Concatenate left || right (32 + 32 = 64 bytes)
            uint8_t combined[64];
            std::memcpy(combined, level[i].data(), 32);
            std::memcpy(combined + 32, level[i + 1].data(), 32);

            next.push_back(keccak256d(combined, 64));
        }

        level = std::move(next);
    }

    return level[0];
}

} // namespace flow
