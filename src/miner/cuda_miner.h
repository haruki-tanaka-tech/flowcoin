// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Host-side API for the CUDA Keccak-256d mining kernel.
//
// Usage from miner.cpp:
//   #ifdef FLOWCOIN_USE_CUDA
//   if (flow::miner::cuda::cuda_init()) {
//       uint32_t nonce = flow::miner::cuda::cuda_mine_batch(
//           header, len, target, start, batch_size);
//   }
//   flow::miner::cuda::cuda_shutdown();
//   #endif

#pragma once

#ifdef FLOWCOIN_USE_CUDA

#include <cstdint>

namespace flow { namespace miner { namespace cuda {

/// Detect GPU, allocate device buffers, print device info.
/// Returns false if no CUDA device is available.
bool cuda_init();

/// Free all device buffers and reset state.
void cuda_shutdown();

/// Mine a batch of nonces on the GPU.
///
/// @param header_data  Unsigned block header bytes (92 bytes typical)
/// @param header_len   Length of header in bytes
/// @param target_data  32-byte target hash (big-endian)
/// @param start_nonce  First nonce to try
/// @param batch_size   Number of nonces to try (e.g. 1<<24 = 16M)
/// @return Winning nonce, or 0 if none found in this batch
uint32_t cuda_mine_batch(
    const uint8_t* header_data, int header_len,
    const uint8_t* target_data,
    uint32_t start_nonce,
    uint32_t batch_size
);

}}} // namespace flow::miner::cuda

#endif // FLOWCOIN_USE_CUDA
