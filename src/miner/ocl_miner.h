/*
 * ocl_miner.h - OpenCL Keccak-256d GPU mining interface.
 * Works on all GPUs: NVIDIA, AMD, Intel, Apple.
 */

#ifndef OCL_MINER_H
#define OCL_MINER_H

#include <stdint.h>
#include <stdbool.h>

/* Initialize OpenCL (find GPU, compile kernel) */
bool ocl_init(void);
void ocl_shutdown(void);

/* GPU info */
const char *ocl_device_name(void);
uint64_t ocl_total_memory(void);

/*
 * Mine a batch of nonces on the GPU.
 *
 * header       : block header bytes
 * header_len   : length of header (e.g. 92)
 * target       : 32-byte target hash
 * nonce_offset : byte offset of nonce field in header (e.g. 76)
 * start_nonce  : first nonce to try
 * batch_size   : number of nonces to try
 * found_nonce  : output — winning nonce if found
 *
 * Returns true if a valid nonce was found.
 */
bool ocl_mine_batch(const uint8_t *header, int header_len,
                    const uint8_t *target,
                    int nonce_offset,
                    uint32_t start_nonce, uint32_t batch_size,
                    uint32_t *found_nonce);

#endif /* OCL_MINER_H */
