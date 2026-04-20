// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Memory pool backed by mlock() / VirtualLock().
// Pages allocated through this pool are locked into physical RAM and will
// never be swapped to disk, protecting sensitive data (private keys,
// seeds, passphrases) from being written to swap partitions in cleartext.
//
// Memory is always zeroed before being returned to the OS.
//
// Usage pattern:
//   auto& pool = flow::locked_pool();
//   void* p = pool.allocate(64);
//   // ... use p for sensitive data ...
//   pool.deallocate(p, 64);  // zeroes before unlocking

#ifndef FLOWCOIN_SUPPORT_LOCKEDPOOL_H
#define FLOWCOIN_SUPPORT_LOCKEDPOOL_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <map>
#include <stdexcept>
#include <vector>

namespace flow {

// ============================================================================
// LockedPageAllocator
// ============================================================================

class LockedPageAllocator {
public:
    LockedPageAllocator();
    ~LockedPageAllocator();

    LockedPageAllocator(const LockedPageAllocator&) = delete;
    LockedPageAllocator& operator=(const LockedPageAllocator&) = delete;

    /// Allocate memory and lock it into physical RAM.
    /// Returns nullptr on failure. The returned memory is zero-filled.
    void* allocate(size_t size);

    /// Securely wipe and unlock a previously allocated region.
    /// The pointer must have been returned by allocate() with the same size.
    void deallocate(void* ptr, size_t size);

    /// Get the total number of bytes currently locked.
    size_t get_locked_bytes() const;

    /// Get the system limit for locked memory (RLIMIT_MEMLOCK on Linux).
    static size_t get_limit();

    /// Get the system page size.
    static size_t get_page_size();

private:
    mutable std::mutex mutex_;
    size_t total_locked_ = 0;

    // Track all allocations for cleanup
    struct Allocation {
        size_t size;
        size_t aligned_size;  // Rounded up to page boundary
    };
    std::map<void*, Allocation> allocations_;

    // Round up to page boundary
    static size_t round_to_page(size_t size);

    // Platform-specific lock/unlock
    static bool lock_pages(void* addr, size_t len);
    static bool unlock_pages(void* addr, size_t len);

    // Platform-specific aligned allocation
    static void* alloc_aligned(size_t alignment, size_t size);
    static void free_aligned(void* ptr);
};

/// Global locked-memory allocator instance.
LockedPageAllocator& locked_pool();

// ============================================================================
// LockedVector — RAII vector backed by locked memory
// ============================================================================

template<typename T>
class LockedVector {
public:
    explicit LockedVector(size_t count = 0) {
        if (count > 0) {
            resize(count);
        }
    }

    ~LockedVector() {
        clear();
    }

    LockedVector(const LockedVector&) = delete;
    LockedVector& operator=(const LockedVector&) = delete;

    LockedVector(LockedVector&& other) noexcept
        : data_(other.data_), size_(other.size_), capacity_(other.capacity_) {
        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }

    LockedVector& operator=(LockedVector&& other) noexcept {
        if (this != &other) {
            clear();
            data_ = other.data_;
            size_ = other.size_;
            capacity_ = other.capacity_;
            other.data_ = nullptr;
            other.size_ = 0;
            other.capacity_ = 0;
        }
        return *this;
    }

    T* data() { return data_; }
    const T* data() const { return data_; }

    size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

    T& operator[](size_t i) { return data_[i]; }
    const T& operator[](size_t i) const { return data_[i]; }

    T& at(size_t i) {
        if (i >= size_) {
            throw std::out_of_range("LockedVector::at");
        }
        return data_[i];
    }

    const T& at(size_t i) const {
        if (i >= size_) {
            throw std::out_of_range("LockedVector::at");
        }
        return data_[i];
    }

    T* begin() { return data_; }
    T* end() { return data_ + size_; }
    const T* begin() const { return data_; }
    const T* end() const { return data_ + size_; }

    void resize(size_t n) {
        if (n == size_) return;

        if (n == 0) {
            clear();
            return;
        }

        size_t new_bytes = n * sizeof(T);
        T* new_data = static_cast<T*>(locked_pool().allocate(new_bytes));
        if (!new_data) return;

        // Copy existing data
        size_t copy_count = (n < size_) ? n : size_;
        if (copy_count > 0 && data_) {
            std::memcpy(new_data, data_, copy_count * sizeof(T));
        }

        // Zero new elements
        if (n > size_) {
            std::memset(new_data + size_, 0, (n - size_) * sizeof(T));
        }

        // Free old data
        if (data_) {
            locked_pool().deallocate(data_, capacity_ * sizeof(T));
        }

        data_ = new_data;
        size_ = n;
        capacity_ = n;
    }

    void clear() {
        if (data_) {
            locked_pool().deallocate(data_, capacity_ * sizeof(T));
            data_ = nullptr;
        }
        size_ = 0;
        capacity_ = 0;
    }

private:
    T* data_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;
};

} // namespace flow

#endif // FLOWCOIN_SUPPORT_LOCKEDPOOL_H
