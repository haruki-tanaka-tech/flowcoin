// Copyright (c) 2026 The FlowCoin Developers
// Distributed under the MIT software license.
//
// Tests for the thread pool (util/threadpool.h).

#include "util/threadpool.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

void test_threadpool() {
    // -----------------------------------------------------------------------
    // Test 1: Create pool and verify worker count
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);
        assert(pool.size() == 4);
        assert(!pool.is_shutdown());
    }

    // -----------------------------------------------------------------------
    // Test 2: Submit a task and get the correct future value
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);
        auto future = pool.submit([]() -> int { return 42; });
        int result = future.get();
        assert(result == 42);
    }

    // -----------------------------------------------------------------------
    // Test 3: Submit returns correct future value for various types
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);

        auto f_int = pool.submit([]() -> int { return 100; });
        auto f_str = pool.submit([]() -> std::string { return "hello"; });
        auto f_dbl = pool.submit([]() -> double { return 3.14; });

        assert(f_int.get() == 100);
        assert(f_str.get() == "hello");
        assert(f_dbl.get() == 3.14);
    }

    // -----------------------------------------------------------------------
    // Test 4: Submit multiple tasks, verify all complete
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);
        constexpr int num_tasks = 100;

        std::atomic<int> counter{0};
        std::vector<std::future<void>> futures;

        for (int i = 0; i < num_tasks; i++) {
            futures.push_back(pool.submit([&counter]() {
                counter.fetch_add(1, std::memory_order_relaxed);
            }));
        }

        for (auto& f : futures) {
            f.get();
        }

        assert(counter.load() == num_tasks);
    }

    // -----------------------------------------------------------------------
    // Test 5: Tasks run in parallel (verify with timing)
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);

        auto start = std::chrono::steady_clock::now();

        // Submit 4 tasks each sleeping 50ms. With 4 threads, should
        // complete in ~50ms, not 200ms.
        std::vector<std::future<void>> futures;
        for (int i = 0; i < 4; i++) {
            futures.push_back(pool.submit([]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }));
        }
        for (auto& f : futures) {
            f.get();
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();

        // Should be around 50ms, definitely less than 150ms
        // (give generous margin for slow CI systems)
        assert(elapsed < 150);
    }

    // -----------------------------------------------------------------------
    // Test 6: shutdown waits for completion
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);
        std::atomic<int> counter{0};

        for (int i = 0; i < 20; i++) {
            pool.submit_detached([&counter]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                counter.fetch_add(1, std::memory_order_relaxed);
            });
        }

        pool.shutdown();
        assert(pool.is_shutdown());
        assert(counter.load() == 20);
    }

    // -----------------------------------------------------------------------
    // Test 7: Zero tasks does not crash
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);
        // Just create and destroy — no tasks submitted
        pool.shutdown();
        assert(pool.is_shutdown());
    }

    // -----------------------------------------------------------------------
    // Test 8: Exception in task does not crash pool
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);

        auto f = pool.submit([]() -> int {
            throw std::runtime_error("test exception");
            return 0;
        });

        bool caught = false;
        try {
            f.get();
        } catch (const std::runtime_error& e) {
            caught = true;
            assert(std::string(e.what()) == "test exception");
        }
        assert(caught);

        // Pool should still work after an exception in a task
        auto f2 = pool.submit([]() -> int { return 99; });
        assert(f2.get() == 99);
    }

    // -----------------------------------------------------------------------
    // Test 9: pending() returns correct count
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(1);  // single thread

        // Submit a blocking task to hold the worker
        std::mutex block_mutex;
        block_mutex.lock();

        pool.submit_detached([&block_mutex]() {
            std::lock_guard<std::mutex> lock(block_mutex);
        });

        // Give the worker a moment to pick up the task
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // Now submit more tasks that will queue up
        pool.submit_detached([]() {});
        pool.submit_detached([]() {});

        size_t pend = pool.pending();
        // There should be at least 2 pending (the blocked task holds the worker)
        assert(pend >= 2);

        // Release the worker
        block_mutex.unlock();

        pool.wait_all();
        assert(pool.pending() == 0);
    }

    // -----------------------------------------------------------------------
    // Test 10: wait_all blocks until tasks complete
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);
        std::atomic<int> sum{0};

        for (int i = 0; i < 50; i++) {
            pool.submit_detached([&sum, i]() {
                sum.fetch_add(i, std::memory_order_relaxed);
            });
        }

        pool.wait_all();

        // Sum of 0..49 = 49*50/2 = 1225
        assert(sum.load() == 1225);
    }

    // -----------------------------------------------------------------------
    // Test 11: Submit after shutdown throws
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);
        pool.shutdown();

        bool threw = false;
        try {
            pool.submit([]() { return 0; });
        } catch (const std::runtime_error&) {
            threw = true;
        }
        assert(threw);
    }

    // -----------------------------------------------------------------------
    // Test 12: ParallelFor works correctly
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);
        constexpr size_t n = 100;
        std::vector<int> results(n, 0);

        flow::ParallelFor(pool, n, [&results](size_t i) {
            results[i] = static_cast<int>(i * i);
        });

        for (size_t i = 0; i < n; i++) {
            assert(results[i] == static_cast<int>(i * i));
        }
    }

    // -----------------------------------------------------------------------
    // Test 13: Single-thread pool works correctly
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(1);
        assert(pool.size() == 1);

        std::vector<std::future<int>> futures;
        for (int i = 0; i < 10; i++) {
            futures.push_back(pool.submit([i]() -> int { return i * 2; }));
        }

        for (int i = 0; i < 10; i++) {
            assert(futures[i].get() == i * 2);
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: submit_detached completes all tasks
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);
        std::atomic<int> counter{0};
        constexpr int num_tasks = 500;

        for (int i = 0; i < num_tasks; i++) {
            pool.submit_detached([&counter]() {
                counter.fetch_add(1, std::memory_order_relaxed);
            });
        }

        pool.wait_all();
        assert(counter.load() == num_tasks);
    }

    // -----------------------------------------------------------------------
    // Test 15: Tasks with different return types
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);

        auto f_bool = pool.submit([]() -> bool { return true; });
        auto f_vec = pool.submit([]() -> std::vector<int> {
            return {1, 2, 3, 4, 5};
        });
        auto f_pair = pool.submit([]() -> std::pair<int, std::string> {
            return {42, "hello"};
        });

        assert(f_bool.get() == true);
        auto vec = f_vec.get();
        assert(vec.size() == 5);
        assert(vec[4] == 5);
        auto pair = f_pair.get();
        assert(pair.first == 42);
        assert(pair.second == "hello");
    }

    // -----------------------------------------------------------------------
    // Test 16: Multiple exceptions don't crash the pool
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);

        std::vector<std::future<int>> futures;
        for (int i = 0; i < 20; i++) {
            futures.push_back(pool.submit([i]() -> int {
                if (i % 3 == 0) {
                    throw std::runtime_error("error at " + std::to_string(i));
                }
                return i;
            }));
        }

        int exceptions = 0;
        int successes = 0;
        for (int i = 0; i < 20; i++) {
            try {
                int val = futures[i].get();
                assert(val == i);
                successes++;
            } catch (const std::runtime_error&) {
                exceptions++;
            }
        }

        // Every third task (0, 3, 6, ...) should throw
        assert(exceptions == 7);  // 0,3,6,9,12,15,18
        assert(successes == 13);
    }

    // -----------------------------------------------------------------------
    // Test 17: active() returns sensible values
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);

        // Before any tasks: active should be 0
        assert(pool.active() == 0);

        // Submit a blocking task
        std::mutex block_mutex;
        block_mutex.lock();

        pool.submit_detached([&block_mutex]() {
            std::lock_guard<std::mutex> lock(block_mutex);
        });

        // Give the worker a moment to start
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        // Should have 1 active task
        assert(pool.active() >= 1);

        block_mutex.unlock();
        pool.wait_all();
        assert(pool.active() == 0);
    }

    // -----------------------------------------------------------------------
    // Test 18: ParallelForEach works with iterators
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);
        std::vector<int> values = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        std::atomic<int> sum{0};

        flow::ParallelForEach(pool, values.begin(), values.end(),
            [&sum](int v) {
                sum.fetch_add(v, std::memory_order_relaxed);
            });

        // Sum of 1..10 = 55
        assert(sum.load() == 55);
    }

    // -----------------------------------------------------------------------
    // Test 19: Large number of small tasks
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);
        constexpr int num_tasks = 10000;
        std::atomic<int> counter{0};

        std::vector<std::future<void>> futures;
        futures.reserve(num_tasks);
        for (int i = 0; i < num_tasks; i++) {
            futures.push_back(pool.submit([&counter]() {
                counter.fetch_add(1, std::memory_order_relaxed);
            }));
        }

        for (auto& f : futures) {
            f.get();
        }

        assert(counter.load() == num_tasks);
    }

    // -----------------------------------------------------------------------
    // Test 20: Pool destruction waits for all tasks
    // -----------------------------------------------------------------------
    {
        std::atomic<int> counter{0};
        {
            flow::ThreadPool pool(2);
            for (int i = 0; i < 50; i++) {
                pool.submit_detached([&counter]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    counter.fetch_add(1, std::memory_order_relaxed);
                });
            }
            // Pool destructor should wait for all tasks
        }
        assert(counter.load() == 50);
    }

    // -----------------------------------------------------------------------
    // Test 21: Double shutdown is safe
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);
        pool.submit_detached([]() {});
        pool.shutdown();
        pool.shutdown();  // second shutdown should not crash
        assert(pool.is_shutdown());
    }

    // -----------------------------------------------------------------------
    // Test 22: wait_all on empty pool returns immediately
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(2);
        pool.wait_all();  // no tasks submitted, should return immediately
    }

    // -----------------------------------------------------------------------
    // Test 23: Compute-intensive tasks complete correctly
    // -----------------------------------------------------------------------
    {
        flow::ThreadPool pool(4);
        constexpr int n = 100;

        std::vector<std::future<uint64_t>> futures;
        for (int i = 0; i < n; i++) {
            futures.push_back(pool.submit([i]() -> uint64_t {
                // Compute fibonacci(i % 30)
                uint64_t a = 0, b = 1;
                int target = i % 30;
                for (int j = 0; j < target; j++) {
                    uint64_t tmp = a + b;
                    a = b;
                    b = tmp;
                }
                return a;
            }));
        }

        // Verify each result against serial computation
        for (int i = 0; i < n; i++) {
            uint64_t a = 0, b = 1;
            int target = i % 30;
            for (int j = 0; j < target; j++) {
                uint64_t tmp = a + b;
                a = b;
                b = tmp;
            }
            assert(futures[i].get() == a);
        }
    }
}
