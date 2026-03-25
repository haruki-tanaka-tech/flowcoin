#ifdef FLOWCOIN_USE_OPENCL
#include "backend_opencl.h"
#include "backend_cpu.h"
#include <cstring>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <string>

namespace flow::miner {

// ----------------------------------------------------------------
// Embedded OpenCL C kernel source
// ----------------------------------------------------------------

static const char* kOpenCLKernelSource = R"opencl(

__kernel void matmul_kernel(__global const float* A,
                            __global const float* B,
                            __global float* C,
                            const int M, const int N, const int K) {
    // C = A @ B^T   A:[M,K]  B:[N,K]  C:[M,N]
    int row = get_global_id(0);
    int col = get_global_id(1);
    if (row >= M || col >= N) return;

    float sum = 0.0f;
    for (int p = 0; p < K; ++p) {
        sum += A[row * K + p] * B[col * K + p];
    }
    C[row * N + col] = sum;
}

__kernel void silu_kernel(__global const float* x,
                          __global float* out,
                          const int n) {
    int i = get_global_id(0);
    if (i >= n) return;
    float val = x[i];
    out[i] = val / (1.0f + exp(-val));
}

__kernel void sigmoid_kernel(__global const float* x,
                             __global float* out,
                             const int n) {
    int i = get_global_id(0);
    if (i >= n) return;
    out[i] = 1.0f / (1.0f + exp(-x[i]));
}

__kernel void mul_kernel(__global const float* a,
                         __global const float* b,
                         __global float* out,
                         const int n) {
    int i = get_global_id(0);
    if (i >= n) return;
    out[i] = a[i] * b[i];
}

__kernel void add_kernel(__global const float* a,
                         __global const float* b,
                         __global float* out,
                         const int n) {
    int i = get_global_id(0);
    if (i >= n) return;
    out[i] = a[i] + b[i];
}

__kernel void sgd_kernel(__global float* weights,
                         __global const float* grads,
                         const float lr,
                         const int n) {
    int i = get_global_id(0);
    if (i >= n) return;
    weights[i] -= lr * grads[i];
}

__kernel void rms_norm_kernel(__global const float* x,
                              __global const float* w,
                              __global float* out,
                              const int cols,
                              __local float* scratch) {
    int row = get_group_id(0);
    int tid = get_local_id(0);
    int local_size = get_local_size(0);

    __global const float* x_row = x + row * cols;
    __global float* out_row = out + row * cols;

    // Sum of squares
    float sum_sq = 0.0f;
    for (int i = tid; i < cols; i += local_size) {
        sum_sq += x_row[i] * x_row[i];
    }
    scratch[tid] = sum_sq;
    barrier(CLK_LOCAL_MEM_FENCE);

    // Reduction
    for (int s = local_size / 2; s > 0; s >>= 1) {
        if (tid < s) scratch[tid] += scratch[tid + s];
        barrier(CLK_LOCAL_MEM_FENCE);
    }

    float rms_inv = rsqrt(scratch[0] / (float)cols + 1e-6f);

    for (int i = tid; i < cols; i += local_size) {
        out_row[i] = x_row[i] * w[i] * rms_inv;
    }
}

__kernel void softmax_kernel(__global const float* x,
                             __global float* out,
                             const int cols,
                             __local float* scratch) {
    int row = get_group_id(0);
    int tid = get_local_id(0);
    int local_size = get_local_size(0);

    __global const float* in = x + row * cols;
    __global float* o = out + row * cols;

    // Find max
    float max_val = -1e30f;
    for (int i = tid; i < cols; i += local_size) {
        max_val = fmax(max_val, in[i]);
    }
    scratch[tid] = max_val;
    barrier(CLK_LOCAL_MEM_FENCE);
    for (int s = local_size / 2; s > 0; s >>= 1) {
        if (tid < s) scratch[tid] = fmax(scratch[tid], scratch[tid + s]);
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    float s_max = scratch[0];
    barrier(CLK_LOCAL_MEM_FENCE);

    // Sum exp
    float sum = 0.0f;
    for (int i = tid; i < cols; i += local_size) {
        sum += exp(in[i] - s_max);
    }
    scratch[tid] = sum;
    barrier(CLK_LOCAL_MEM_FENCE);
    for (int s = local_size / 2; s > 0; s >>= 1) {
        if (tid < s) scratch[tid] += scratch[tid + s];
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    float s_sum = scratch[0];
    barrier(CLK_LOCAL_MEM_FENCE);

    float inv_sum = 1.0f / s_sum;
    for (int i = tid; i < cols; i += local_size) {
        o[i] = exp(in[i] - s_max) * inv_sum;
    }
}

)opencl";

// ----------------------------------------------------------------
// Init / Shutdown
// ----------------------------------------------------------------

bool OpenCLBackend::build_kernels() {
    cl_int err;

    const char* src = kOpenCLKernelSource;
    size_t src_len = std::strlen(src);
    program_ = clCreateProgramWithSource(context_, 1, &src, &src_len, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: failed to create program: %d\n", err);
        return false;
    }

    err = clBuildProgram(program_, 1, &device_id_, "-cl-fast-relaxed-math", nullptr, nullptr);
    if (err != CL_SUCCESS) {
        // Print build log
        size_t log_len = 0;
        clGetProgramBuildInfo(program_, device_id_, CL_PROGRAM_BUILD_LOG,
                              0, nullptr, &log_len);
        std::vector<char> log(log_len + 1);
        clGetProgramBuildInfo(program_, device_id_, CL_PROGRAM_BUILD_LOG,
                              log_len, log.data(), nullptr);
        fprintf(stderr, "OpenCL build error:\n%s\n", log.data());
        return false;
    }

    k_matmul_   = clCreateKernel(program_, "matmul_kernel", &err);
    k_silu_     = clCreateKernel(program_, "silu_kernel", &err);
    k_sigmoid_  = clCreateKernel(program_, "sigmoid_kernel", &err);
    k_mul_      = clCreateKernel(program_, "mul_kernel", &err);
    k_add_      = clCreateKernel(program_, "add_kernel", &err);
    k_sgd_      = clCreateKernel(program_, "sgd_kernel", &err);
    k_rms_norm_ = clCreateKernel(program_, "rms_norm_kernel", &err);
    k_softmax_  = clCreateKernel(program_, "softmax_kernel", &err);

    return true;
}

bool OpenCLBackend::init() {
    if (initialized_) return true;

    cl_int err;

    // Get platform
    cl_uint num_platforms = 0;
    err = clGetPlatformIDs(0, nullptr, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        fprintf(stderr, "OpenCL: no platforms found\n");
        return false;
    }

    std::vector<cl_platform_id> platforms(num_platforms);
    clGetPlatformIDs(num_platforms, platforms.data(), nullptr);
    platform_ = platforms[0];

    // Get GPU device (fall back to any device)
    err = clGetDeviceIDs(platform_, CL_DEVICE_TYPE_GPU, 1, &device_id_, nullptr);
    if (err != CL_SUCCESS) {
        err = clGetDeviceIDs(platform_, CL_DEVICE_TYPE_ALL, 1, &device_id_, nullptr);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "OpenCL: no devices found\n");
            return false;
        }
    }

    // Create context and command queue
    context_ = clCreateContext(nullptr, 1, &device_id_, nullptr, nullptr, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: failed to create context\n");
        return false;
    }

    queue_ = clCreateCommandQueue(context_, device_id_, 0, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: failed to create command queue\n");
        clReleaseContext(context_);
        context_ = nullptr;
        return false;
    }

    if (!build_kernels()) {
        clReleaseCommandQueue(queue_);
        clReleaseContext(context_);
        queue_ = nullptr;
        context_ = nullptr;
        return false;
    }

    initialized_ = true;
    return true;
}

void OpenCLBackend::shutdown() {
    if (!initialized_) return;

    if (k_matmul_)   clReleaseKernel(k_matmul_);
    if (k_silu_)     clReleaseKernel(k_silu_);
    if (k_sigmoid_)  clReleaseKernel(k_sigmoid_);
    if (k_mul_)      clReleaseKernel(k_mul_);
    if (k_add_)      clReleaseKernel(k_add_);
    if (k_sgd_)      clReleaseKernel(k_sgd_);
    if (k_rms_norm_) clReleaseKernel(k_rms_norm_);
    if (k_softmax_)  clReleaseKernel(k_softmax_);
    if (program_)    clReleaseProgram(program_);
    if (queue_)      clReleaseCommandQueue(queue_);
    if (context_)    clReleaseContext(context_);

    k_matmul_ = k_silu_ = k_sigmoid_ = k_mul_ = nullptr;
    k_add_ = k_sgd_ = k_rms_norm_ = k_softmax_ = nullptr;
    program_ = nullptr;
    queue_ = nullptr;
    context_ = nullptr;
    initialized_ = false;
}

// ----------------------------------------------------------------
// Device info
// ----------------------------------------------------------------

std::string OpenCLBackend::device_name() const {
    char buf[256] = {};
    clGetDeviceInfo(device_id_, CL_DEVICE_NAME, sizeof(buf), buf, nullptr);
    return std::string(buf);
}

size_t OpenCLBackend::total_memory() const {
    cl_ulong mem = 0;
    clGetDeviceInfo(device_id_, CL_DEVICE_GLOBAL_MEM_SIZE,
                    sizeof(mem), &mem, nullptr);
    return static_cast<size_t>(mem);
}

size_t OpenCLBackend::available_memory() const {
    // OpenCL does not expose free memory directly
    return total_memory();
}

// ----------------------------------------------------------------
// Memory management
// ----------------------------------------------------------------

struct CLAlloc {
    cl_mem buffer;
    size_t size;
};

void* OpenCLBackend::alloc(size_t bytes) {
    cl_int err;
    cl_mem buffer = clCreateBuffer(context_, CL_MEM_READ_WRITE, bytes,
                                   nullptr, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: alloc failed: %d\n", err);
        return nullptr;
    }
    auto* handle = new CLAlloc{buffer, bytes};
    return static_cast<void*>(handle);
}

void OpenCLBackend::free(void* ptr) {
    if (!ptr) return;
    auto* handle = static_cast<CLAlloc*>(ptr);
    clReleaseMemObject(handle->buffer);
    delete handle;
}

void OpenCLBackend::upload(void* dst, const float* src, size_t count) {
    auto* handle = static_cast<CLAlloc*>(dst);
    clEnqueueWriteBuffer(queue_, handle->buffer, CL_TRUE, 0,
                         count * sizeof(float), src, 0, nullptr, nullptr);
}

void OpenCLBackend::download(float* dst, const void* src, size_t count) {
    auto* handle = static_cast<const CLAlloc*>(src);
    clEnqueueReadBuffer(queue_, handle->buffer, CL_TRUE, 0,
                        count * sizeof(float), dst, 0, nullptr, nullptr);
}

// ----------------------------------------------------------------
// Helper: get cl_mem from handle
// ----------------------------------------------------------------

static cl_mem cl_buf(const void* handle) {
    return static_cast<const CLAlloc*>(handle)->buffer;
}

// ----------------------------------------------------------------
// Compute operations
// ----------------------------------------------------------------

void OpenCLBackend::matmul(const void* A, const void* B, void* C,
                           int M, int N, int K) {
    cl_mem a_buf = cl_buf(A);
    cl_mem b_buf = cl_buf(B);
    cl_mem c_buf = cl_buf(C);

    clSetKernelArg(k_matmul_, 0, sizeof(cl_mem), &a_buf);
    clSetKernelArg(k_matmul_, 1, sizeof(cl_mem), &b_buf);
    clSetKernelArg(k_matmul_, 2, sizeof(cl_mem), &c_buf);
    clSetKernelArg(k_matmul_, 3, sizeof(int), &M);
    clSetKernelArg(k_matmul_, 4, sizeof(int), &N);
    clSetKernelArg(k_matmul_, 5, sizeof(int), &K);

    size_t global[2] = {static_cast<size_t>(M), static_cast<size_t>(N)};
    clEnqueueNDRangeKernel(queue_, k_matmul_, 2, nullptr, global,
                           nullptr, 0, nullptr, nullptr);
    clFinish(queue_);
}

void OpenCLBackend::rms_norm(const void* x, const void* w, void* out,
                             int rows, int cols) {
    cl_mem x_buf = cl_buf(x);
    cl_mem w_buf = cl_buf(w);
    cl_mem o_buf = cl_buf(out);

    clSetKernelArg(k_rms_norm_, 0, sizeof(cl_mem), &x_buf);
    clSetKernelArg(k_rms_norm_, 1, sizeof(cl_mem), &w_buf);
    clSetKernelArg(k_rms_norm_, 2, sizeof(cl_mem), &o_buf);
    clSetKernelArg(k_rms_norm_, 3, sizeof(int), &cols);

    size_t local_size = 256;
    size_t scratch_size = local_size * sizeof(float);
    clSetKernelArg(k_rms_norm_, 4, scratch_size, nullptr);

    size_t global = static_cast<size_t>(rows) * local_size;
    clEnqueueNDRangeKernel(queue_, k_rms_norm_, 1, nullptr, &global,
                           &local_size, 0, nullptr, nullptr);
    clFinish(queue_);
}

void OpenCLBackend::silu(const void* x, void* out, int n) {
    cl_mem x_buf = cl_buf(x);
    cl_mem o_buf = cl_buf(out);

    clSetKernelArg(k_silu_, 0, sizeof(cl_mem), &x_buf);
    clSetKernelArg(k_silu_, 1, sizeof(cl_mem), &o_buf);
    clSetKernelArg(k_silu_, 2, sizeof(int), &n);

    size_t global = static_cast<size_t>((n + 255) / 256) * 256;
    size_t local = 256;
    clEnqueueNDRangeKernel(queue_, k_silu_, 1, nullptr, &global,
                           &local, 0, nullptr, nullptr);
    clFinish(queue_);
}

void OpenCLBackend::sigmoid(const void* x, void* out, int n) {
    cl_mem x_buf = cl_buf(x);
    cl_mem o_buf = cl_buf(out);

    clSetKernelArg(k_sigmoid_, 0, sizeof(cl_mem), &x_buf);
    clSetKernelArg(k_sigmoid_, 1, sizeof(cl_mem), &o_buf);
    clSetKernelArg(k_sigmoid_, 2, sizeof(int), &n);

    size_t global = static_cast<size_t>((n + 255) / 256) * 256;
    size_t local = 256;
    clEnqueueNDRangeKernel(queue_, k_sigmoid_, 1, nullptr, &global,
                           &local, 0, nullptr, nullptr);
    clFinish(queue_);
}

void OpenCLBackend::mul(const void* a, const void* b, void* out, int n) {
    cl_mem a_buf = cl_buf(a);
    cl_mem b_buf = cl_buf(b);
    cl_mem o_buf = cl_buf(out);

    clSetKernelArg(k_mul_, 0, sizeof(cl_mem), &a_buf);
    clSetKernelArg(k_mul_, 1, sizeof(cl_mem), &b_buf);
    clSetKernelArg(k_mul_, 2, sizeof(cl_mem), &o_buf);
    clSetKernelArg(k_mul_, 3, sizeof(int), &n);

    size_t global = static_cast<size_t>((n + 255) / 256) * 256;
    size_t local = 256;
    clEnqueueNDRangeKernel(queue_, k_mul_, 1, nullptr, &global,
                           &local, 0, nullptr, nullptr);
    clFinish(queue_);
}

void OpenCLBackend::add(const void* a, const void* b, void* out, int n) {
    cl_mem a_buf = cl_buf(a);
    cl_mem b_buf = cl_buf(b);
    cl_mem o_buf = cl_buf(out);

    clSetKernelArg(k_add_, 0, sizeof(cl_mem), &a_buf);
    clSetKernelArg(k_add_, 1, sizeof(cl_mem), &b_buf);
    clSetKernelArg(k_add_, 2, sizeof(cl_mem), &o_buf);
    clSetKernelArg(k_add_, 3, sizeof(int), &n);

    size_t global = static_cast<size_t>((n + 255) / 256) * 256;
    size_t local = 256;
    clEnqueueNDRangeKernel(queue_, k_add_, 1, nullptr, &global,
                           &local, 0, nullptr, nullptr);
    clFinish(queue_);
}

void OpenCLBackend::softmax(const void* x, void* out, int rows, int cols) {
    cl_mem x_buf = cl_buf(x);
    cl_mem o_buf = cl_buf(out);

    clSetKernelArg(k_softmax_, 0, sizeof(cl_mem), &x_buf);
    clSetKernelArg(k_softmax_, 1, sizeof(cl_mem), &o_buf);
    clSetKernelArg(k_softmax_, 2, sizeof(int), &cols);

    size_t local_size = 256;
    size_t scratch_size = local_size * sizeof(float);
    clSetKernelArg(k_softmax_, 3, scratch_size, nullptr);

    size_t global = static_cast<size_t>(rows) * local_size;
    clEnqueueNDRangeKernel(queue_, k_softmax_, 1, nullptr, &global,
                           &local_size, 0, nullptr, nullptr);
    clFinish(queue_);
}

float OpenCLBackend::cross_entropy(const void* logits, const uint8_t* targets,
                                   int seq_len, int vocab) {
    // CPU fallback: download logits, compute on host
    std::vector<float> h_logits(seq_len * vocab);
    download(h_logits.data(), logits, seq_len * vocab);

    CPUBackend cpu;
    return cpu.cross_entropy(h_logits.data(), targets, seq_len, vocab);
}

void OpenCLBackend::topk(const void* scores, int* indices, float* values,
                         int n, int k) {
    // CPU fallback
    std::vector<float> h_scores(n);
    download(h_scores.data(), scores, n);

    CPUBackend cpu;
    cpu.topk(h_scores.data(), indices, values, n, k);
}

void OpenCLBackend::sgd_update(void* weights, const void* grads,
                               float lr, int n) {
    cl_mem w_buf = cl_buf(weights);
    cl_mem g_buf = cl_buf(grads);

    clSetKernelArg(k_sgd_, 0, sizeof(cl_mem), &w_buf);
    clSetKernelArg(k_sgd_, 1, sizeof(cl_mem), &g_buf);
    clSetKernelArg(k_sgd_, 2, sizeof(float), &lr);
    clSetKernelArg(k_sgd_, 3, sizeof(int), &n);

    size_t global = static_cast<size_t>((n + 255) / 256) * 256;
    size_t local = 256;
    clEnqueueNDRangeKernel(queue_, k_sgd_, 1, nullptr, &global,
                           &local, 0, nullptr, nullptr);
    clFinish(queue_);
}

void OpenCLBackend::sync() {
    if (queue_) clFinish(queue_);
}

} // namespace flow::miner

#endif // FLOWCOIN_USE_OPENCL
