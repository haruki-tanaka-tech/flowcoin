// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// CUDA Keccak-256d mining kernel (placeholder).
// This file is only compiled when FLOWCOIN_USE_CUDA is enabled.

#ifdef FLOWCOIN_USE_CUDA

#include <cstdint>

// Placeholder - full CUDA Keccak-256d implementation to be added
__global__ void keccak256d_mine_kernel(
    const uint8_t* header_base,
    uint32_t start_nonce,
    const uint8_t* target,
    uint32_t* found_nonce,
    bool* found_flag
) {
    // TODO: implement Keccak-256d mining kernel
    (void)header_base;
    (void)start_nonce;
    (void)target;
    (void)found_nonce;
    (void)found_flag;
}

#endif // FLOWCOIN_USE_CUDA
