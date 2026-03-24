// Copyright (c) 2026 Haruki Tanaka
// Distributed under the MIT software license

#include "threadpool.h"

namespace flow {

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

ThreadPool::ThreadPool(size_t num_threads) {
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) {
            num_threads = 4;  // reasonable default
        }
    }

    workers_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this]() { worker_loop(); });
    }
}

// ---------------------------------------------------------------------------
// Destructor
// ---------------------------------------------------------------------------

ThreadPool::~ThreadPool() {
    shutdown();
}

// ---------------------------------------------------------------------------
// submit_detached
// ---------------------------------------------------------------------------

void ThreadPool::submit_detached(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stop_.load(std::memory_order_relaxed)) {
            return;  // silently drop tasks after shutdown for detached
        }
        tasks_.emplace(std::move(task));
    }
    cv_.notify_one();
}

// ---------------------------------------------------------------------------
// wait_all
// ---------------------------------------------------------------------------

void ThreadPool::wait_all() {
    std::unique_lock<std::mutex> lock(mutex_);
    done_cv_.wait(lock, [this]() {
        return tasks_.empty() && active_.load(std::memory_order_relaxed) == 0;
    });
}

// ---------------------------------------------------------------------------
// pending
// ---------------------------------------------------------------------------

size_t ThreadPool::pending() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tasks_.size();
}

// ---------------------------------------------------------------------------
// shutdown
// ---------------------------------------------------------------------------

void ThreadPool::shutdown() {
    // Only shut down once
    bool expected = false;
    if (!stop_.compare_exchange_strong(expected, true)) {
        return;  // already shutting down or shut down
    }

    // Wake all workers so they can see the stop flag
    cv_.notify_all();

    // Join all worker threads
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

// ---------------------------------------------------------------------------
// worker_loop
// ---------------------------------------------------------------------------

void ThreadPool::worker_loop() {
    for (;;) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(mutex_);

            // Wait for a task or shutdown signal.
            cv_.wait(lock, [this]() {
                return stop_.load(std::memory_order_relaxed) || !tasks_.empty();
            });

            // If stopping and no more tasks, exit.
            if (stop_.load(std::memory_order_relaxed) && tasks_.empty()) {
                return;
            }

            // Take a task from the queue.
            if (tasks_.empty()) {
                continue;
            }
            task = std::move(tasks_.front());
            tasks_.pop();

            active_.fetch_add(1, std::memory_order_relaxed);
        }

        // Execute the task outside the lock.
        task();

        // Mark this worker as idle.
        active_.fetch_sub(1, std::memory_order_relaxed);

        // Notify wait_all() if queue is empty and no workers are active.
        done_cv_.notify_all();
    }
}

} // namespace flow
