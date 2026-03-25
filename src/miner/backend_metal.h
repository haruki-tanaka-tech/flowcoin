#pragma once
#include "backend.h"

#ifdef FLOWCOIN_USE_METAL

namespace flow::miner {

// Forward declaration for the Objective-C++ implementation detail
struct MetalContext;

class MetalBackend : public ComputeBackend {
public:
    MetalBackend() = default;
    ~MetalBackend() override { shutdown(); }

    BackendType type() const override { return BackendType::METAL; }
    std::string name() const override { return "Metal"; }
    bool init() override;
    void shutdown() override;

    std::string device_name() const override;
    size_t total_memory() const override;
    size_t available_memory() const override;

    void* alloc(size_t bytes) override;
    void free(void* ptr) override;
    void upload(void* dst, const float* src, size_t count) override;
    void download(float* dst, const void* src, size_t count) override;

    void matmul(const void* A, const void* B, void* C,
                int M, int N, int K) override;
    void rms_norm(const void* x, const void* w, void* out,
                  int rows, int cols) override;
    void silu(const void* x, void* out, int n) override;
    void sigmoid(const void* x, void* out, int n) override;
    void mul(const void* a, const void* b, void* out, int n) override;
    void add(const void* a, const void* b, void* out, int n) override;
    void softmax(const void* x, void* out, int rows, int cols) override;
    float cross_entropy(const void* logits, const uint8_t* targets,
                        int seq_len, int vocab) override;
    void topk(const void* scores, int* indices, float* values,
              int n, int k) override;
    void sgd_update(void* weights, const void* grads,
                    float lr, int n) override;
    void sync() override;

private:
    MetalContext* ctx_ = nullptr;
    bool initialized_ = false;
};

} // namespace flow::miner

#endif // FLOWCOIN_USE_METAL
