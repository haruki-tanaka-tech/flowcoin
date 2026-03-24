// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Cryptographically secure random number generation using /dev/urandom.
// The file descriptor is opened once (on first use) and kept open for
// the lifetime of the process.

#include "random.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace flow {

// ---------------------------------------------------------------------------
// Internal: persistent /dev/urandom file descriptor
// ---------------------------------------------------------------------------

/** Open /dev/urandom once and cache the file descriptor.
 *  Fatal error if it cannot be opened.
 */
static int GetUrandomFD() {
    static int fd = -1;
    if (fd == -1) {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            std::fprintf(stderr, "FATAL: failed to open /dev/urandom: %s\n",
                         std::strerror(errno));
            std::abort();
        }
    }
    return fd;
}

// ---------------------------------------------------------------------------
// GetRandBytes — fill buffer with secure random data
// ---------------------------------------------------------------------------

void GetRandBytes(uint8_t* buf, size_t len) {
    int fd = GetUrandomFD();
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;  // interrupted by signal, retry
            std::fprintf(stderr, "FATAL: read from /dev/urandom failed: %s\n",
                         std::strerror(errno));
            std::abort();
        }
        if (n == 0) {
            // Should never happen with /dev/urandom.
            std::fprintf(stderr, "FATAL: /dev/urandom returned EOF\n");
            std::abort();
        }
        total += static_cast<size_t>(n);
    }
}

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

uint64_t GetRandUint64() {
    uint64_t v;
    GetRandBytes(reinterpret_cast<uint8_t*>(&v), sizeof(v));
    return v;
}

uint256 GetRandUint256() {
    uint256 v;
    GetRandBytes(v.data(), uint256::size());
    return v;
}

} // namespace flow
