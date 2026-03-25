#pragma once
#include "backend.h"

#ifdef FLOWCOIN_USE_OPENCL

#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.h>

namespace flow::miner {

class OpenCLBackend : public ComputeBackend {
public:
    OpenCLBackend() = default;
    ~OpenCLBackend() override { shutdown(); }

    BackendType type() const override { return BackendType::OPENCL; }
    std::string name() const override { return "OpenCL"; }
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
    cl_platform_id platform_ = nullptr;
    cl_device_id device_id_ = nullptr;
    cl_context context_ = nullptr;
    cl_command_queue queue_ = nullptr;
    cl_program program_ = nullptr;

    // Compiled kernels
    cl_kernel k_matmul_ = nullptr;
    cl_kernel k_silu_ = nullptr;
    cl_kernel k_sigmoid_ = nullptr;
    cl_kernel k_mul_ = nullptr;
    cl_kernel k_add_ = nullptr;
    cl_kernel k_sgd_ = nullptr;
    cl_kernel k_rms_norm_ = nullptr;
    cl_kernel k_softmax_ = nullptr;

    bool initialized_ = false;

    bool build_kernels();
};

} // namespace flow::miner

#endif // FLOWCOIN_USE_OPENCL
