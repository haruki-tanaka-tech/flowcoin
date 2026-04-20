// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.

#include "support/lockedpool.h"
#include "support/cleanse.h"

#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace flow {

// ============================================================================
// Platform-specific helpers
// ============================================================================

size_t LockedPageAllocator::get_page_size() {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return static_cast<size_t>(si.dwPageSize);
#else
    long ps = sysconf(_SC_PAGESIZE);
    return (ps > 0) ? static_cast<size_t>(ps) : 4096;
#endif
}

size_t LockedPageAllocator::round_to_page(size_t size) {
    size_t ps = get_page_size();
    return (size + ps - 1) & ~(ps - 1);
}

bool LockedPageAllocator::lock_pages(void* addr, size_t len) {
#ifdef _WIN32
    return VirtualLock(addr, len) != 0;
#else
    return mlock(addr, len) == 0;
#endif
}

bool LockedPageAllocator::unlock_pages(void* addr, size_t len) {
#ifdef _WIN32
    return VirtualUnlock(addr, len) != 0;
#else
    return munlock(addr, len) == 0;
#endif
}

void* LockedPageAllocator::alloc_aligned(size_t alignment, size_t size) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    void* ptr = nullptr;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return nullptr;
    }
    return ptr;
#endif
}

void LockedPageAllocator::free_aligned(void* ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

// ============================================================================
// LockedPageAllocator implementation
// ============================================================================

LockedPageAllocator::LockedPageAllocator() = default;

LockedPageAllocator::~LockedPageAllocator() {
    // Clean up all remaining allocations
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [ptr, alloc] : allocations_) {
        memory_cleanse(ptr, alloc.size);
        unlock_pages(ptr, alloc.aligned_size);
        free_aligned(ptr);
    }
    allocations_.clear();
    total_locked_ = 0;
}

void* LockedPageAllocator::allocate(size_t size) {
    if (size == 0) return nullptr;

    size_t page_size = get_page_size();
    size_t aligned_size = round_to_page(size);

    // Allocate page-aligned memory
    void* ptr = alloc_aligned(page_size, aligned_size);
    if (!ptr) return nullptr;

    // Zero the memory
    std::memset(ptr, 0, aligned_size);

    // Lock it into RAM
    if (!lock_pages(ptr, aligned_size)) {
        // Lock failed (probably hit RLIMIT_MEMLOCK).
        // Still usable, just not guaranteed to avoid swap.
        // In production, log a warning. For now, continue.
    }

    // Advise the kernel not to include this memory in core dumps
#if defined(__linux__) && defined(MADV_DONTDUMP)
    madvise(ptr, aligned_size, MADV_DONTDUMP);
#endif

    std::lock_guard<std::mutex> lock(mutex_);
    allocations_[ptr] = {size, aligned_size};
    total_locked_ += aligned_size;

    return ptr;
}

void LockedPageAllocator::deallocate(void* ptr, size_t size) {
    if (!ptr) return;

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(ptr);
    if (it == allocations_.end()) {
        // Not our allocation -- just cleanse and return.
        // This shouldn't happen in correct usage.
        memory_cleanse(ptr, size);
        return;
    }

    Allocation alloc = it->second;
    allocations_.erase(it);

    // Securely wipe the entire allocated region
    memory_cleanse(ptr, alloc.aligned_size);

    // Unlock pages
    unlock_pages(ptr, alloc.aligned_size);

    // Allow kernel to dump again (undo MADV_DONTDUMP)
#if defined(__linux__) && defined(MADV_DODUMP)
    madvise(ptr, alloc.aligned_size, MADV_DODUMP);
#endif

    total_locked_ -= alloc.aligned_size;

    free_aligned(ptr);
}

size_t LockedPageAllocator::get_locked_bytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_locked_;
}

size_t LockedPageAllocator::get_limit() {
#ifdef _WIN32
    // Windows doesn't have a simple query for the lock limit.
    // Working set size is managed by the OS.
    SIZE_T min_ws = 0, max_ws = 0;
    GetProcessWorkingSetSize(GetCurrentProcess(), &min_ws, &max_ws);
    return static_cast<size_t>(max_ws);
#else
    struct rlimit rl;
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
        if (rl.rlim_cur == RLIM_INFINITY) {
            return static_cast<size_t>(-1);
        }
        return static_cast<size_t>(rl.rlim_cur);
    }
    return 65536;  // Conservative fallback: 64KB
#endif
}

// ============================================================================
// Global instance
// ============================================================================

LockedPageAllocator& locked_pool() {
    static LockedPageAllocator instance;
    return instance;
}

} // namespace flow
