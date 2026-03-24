// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license
//
// Thread pool for parallel validation, signature checking, and other
// CPU-bound tasks in FlowCoin.
//
// Uses a fixed number of worker threads that pull tasks from a shared queue.
// Supports futures for getting task results and wait_all() for synchronization.

#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <vector>

namespace flow {

class ThreadPool {
public:
    /// Create a thread pool with the given number of worker threads.
    /// If num_threads is 0, uses std::thread::hardware_concurrency().
    /// If hardware_concurrency() returns 0, defaults to 4 threads.
    explicit ThreadPool(size_t num_threads = 0);

    /// Destructor: waits for all tasks to complete, then shuts down.
    ~ThreadPool();

    /// Submit a callable task and get a future for the result.
    /// Throws std::runtime_error if the pool has been shut down.
    template<typename F, typename... Args>
    auto submit(F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>>;

    /// Submit a void task without caring about the result.
    void submit_detached(std::function<void()> task);

    /// Wait for all currently submitted tasks to complete.
    /// This blocks until both the task queue is empty and all workers are idle.
    void wait_all();

    /// Get the number of worker threads.
    size_t size() const { return workers_.size(); }

    /// Get the number of pending tasks in the queue.
    size_t pending() const;

    /// Get the number of currently active (executing) tasks.
    size_t active() const { return active_.load(std::memory_order_relaxed); }

    /// Check if the pool has been shut down.
    bool is_shutdown() const { return stop_.load(std::memory_order_relaxed); }

    /// Shut down the pool: finish all pending tasks, then stop workers.
    /// Called automatically by the destructor. Safe to call multiple times.
    void shutdown();

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;       // Workers wait on this
    std::condition_variable done_cv_;  // wait_all() waits on this
    std::atomic<size_t> active_{0};
    std::atomic<bool> stop_{false};

    /// Worker thread main loop.
    void worker_loop();
};

// ===========================================================================
// Template implementation (must be in header)
// ===========================================================================

template<typename F, typename... Args>
auto ThreadPool::submit(F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>> {
    using return_type = std::invoke_result_t<F, Args...>;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );

    std::future<return_type> result = task->get_future();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stop_.load(std::memory_order_relaxed)) {
            throw std::runtime_error("ThreadPool: cannot submit task after shutdown");
        }
        tasks_.emplace([task]() { (*task)(); });
    }

    cv_.notify_one();
    return result;
}

// ---------------------------------------------------------------------------
// ParallelForEach -- convenience for parallel iteration
// ---------------------------------------------------------------------------

/// Execute a function on each element of a range in parallel using the
/// given thread pool. Blocks until all elements are processed.
template<typename Iterator, typename Func>
void ParallelForEach(ThreadPool& pool, Iterator begin, Iterator end, Func func) {
    std::vector<std::future<void>> futures;
    for (auto it = begin; it != end; ++it) {
        futures.push_back(pool.submit([&func, it]() { func(*it); }));
    }
    for (auto& f : futures) {
        f.get();
    }
}

/// Execute a function on indices [0, count) in parallel.
template<typename Func>
void ParallelFor(ThreadPool& pool, size_t count, Func func) {
    std::vector<std::future<void>> futures;
    futures.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        futures.push_back(pool.submit([&func, i]() { func(i); }));
    }
    for (auto& f : futures) {
        f.get();
    }
}

} // namespace flow
