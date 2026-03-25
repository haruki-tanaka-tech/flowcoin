#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>
#include <vector>

namespace flow::miner {

// Backend capabilities
enum class BackendType {
    CPU,
    CUDA,
    METAL,
    VULKAN,
    OPENCL,
};

// Abstract GPU compute backend
class ComputeBackend {
public:
    virtual ~ComputeBackend() = default;

    virtual BackendType type() const = 0;
    virtual std::string name() const = 0;
    virtual bool init() = 0;
    virtual void shutdown() = 0;

    // Device info
    virtual std::string device_name() const = 0;
    virtual size_t total_memory() const = 0;
    virtual size_t available_memory() const = 0;

    // ----------------------------------------------------------------
    // Core operations
    // ----------------------------------------------------------------

    // Allocate device memory, returns opaque handle
    virtual void* alloc(size_t bytes) = 0;
    virtual void free(void* ptr) = 0;

    // Copy host -> device
    virtual void upload(void* dst, const float* src, size_t count) = 0;
    // Copy device -> host
    virtual void download(float* dst, const void* src, size_t count) = 0;

    // Matrix multiply: C = A @ B^T   (A:[M,K], B:[N,K], C:[M,N])
    virtual void matmul(const void* A, const void* B, void* C,
                        int M, int N, int K) = 0;

    // Element-wise operations (in-place or out-of-place)
    virtual void rms_norm(const void* x, const void* w, void* out,
                          int rows, int cols) = 0;
    virtual void silu(const void* x, void* out, int n) = 0;
    virtual void sigmoid(const void* x, void* out, int n) = 0;
    virtual void mul(const void* a, const void* b, void* out, int n) = 0;
    virtual void add(const void* a, const void* b, void* out, int n) = 0;
    virtual void softmax(const void* x, void* out, int rows, int cols) = 0;

    // Cross-entropy loss (returns scalar on host)
    virtual float cross_entropy(const void* logits, const uint8_t* targets,
                                int seq_len, int vocab) = 0;

    // Top-k (returns indices and values on host)
    virtual void topk(const void* scores, int* indices, float* values,
                      int n, int k) = 0;

    // SGD update: w -= lr * grad
    virtual void sgd_update(void* weights, const void* grads,
                            float lr, int n) = 0;

    // Synchronize (wait for all GPU operations to complete)
    virtual void sync() = 0;
};

// ----------------------------------------------------------------
// Backend factory
// ----------------------------------------------------------------
std::unique_ptr<ComputeBackend> create_backend(BackendType type);
std::unique_ptr<ComputeBackend> create_best_backend();
std::vector<BackendType> available_backends();
std::string backend_name(BackendType type);

} // namespace flow::miner
