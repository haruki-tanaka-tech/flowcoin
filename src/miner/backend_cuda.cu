#ifdef FLOWCOIN_USE_CUDA
#include "backend_cuda.h"
#include <cuda_runtime.h>
#include <cublas_v2.h>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <vector>
#include <numeric>
#include <cmath>

namespace flow::miner {

// ----------------------------------------------------------------
// cuBLAS handle (module-level)
// ----------------------------------------------------------------

static cublasHandle_t g_cublas = nullptr;

// Helper: check CUDA errors
#define CUDA_CHECK(call)                                                \
    do {                                                                \
        cudaError_t err = (call);                                       \
        if (err != cudaSuccess) {                                       \
            fprintf(stderr, "CUDA error at %s:%d: %s\n",               \
                    __FILE__, __LINE__, cudaGetErrorString(err));        \
            return;                                                     \
        }                                                               \
    } while (0)

#define CUDA_CHECK_BOOL(call)                                           \
    do {                                                                \
        cudaError_t err = (call);                                       \
        if (err != cudaSuccess) {                                       \
            fprintf(stderr, "CUDA error at %s:%d: %s\n",               \
                    __FILE__, __LINE__, cudaGetErrorString(err));        \
            return false;                                               \
        }                                                               \
    } while (0)

// ----------------------------------------------------------------
// Kernel launch helpers
// ----------------------------------------------------------------

static constexpr int kBlockSize = 256;

static int grid_size(int n) {
    return (n + kBlockSize - 1) / kBlockSize;
}

// ----------------------------------------------------------------
// CUDA Kernels
// ----------------------------------------------------------------

__global__ void rms_norm_kernel(const float* __restrict__ x,
                                const float* __restrict__ w,
                                float* __restrict__ out,
                                int rows, int cols) {
    int row = blockIdx.x;
    if (row >= rows) return;

    const float* x_row = x + row * cols;
    float* out_row = out + row * cols;

    // Compute sum of squares via warp/block reduction
    float sum_sq = 0.0f;
    for (int i = threadIdx.x; i < cols; i += blockDim.x) {
        sum_sq += x_row[i] * x_row[i];
    }

    // Warp-level reduction
    for (int offset = warpSize / 2; offset > 0; offset >>= 1)
        sum_sq += __shfl_down_sync(0xffffffff, sum_sq, offset);

    // Block-level reduction via shared memory for multi-warp blocks
    __shared__ float warp_sums[8]; // up to 256 threads = 8 warps
    int lane = threadIdx.x % warpSize;
    int warp_id = threadIdx.x / warpSize;

    if (lane == 0)
        warp_sums[warp_id] = sum_sq;
    __syncthreads();

    // First warp reduces the warp sums
    if (warp_id == 0) {
        float val = (lane < (blockDim.x + warpSize - 1) / warpSize)
                        ? warp_sums[lane] : 0.0f;
        for (int offset = warpSize / 2; offset > 0; offset >>= 1)
            val += __shfl_down_sync(0xffffffff, val, offset);
        if (lane == 0)
            warp_sums[0] = val;
    }
    __syncthreads();

    float rms_inv = rsqrtf(warp_sums[0] / static_cast<float>(cols) + 1e-6f);

    for (int i = threadIdx.x; i < cols; i += blockDim.x) {
        out_row[i] = x_row[i] * w[i] * rms_inv;
    }
}

__global__ void silu_kernel(const float* __restrict__ x,
                            float* __restrict__ out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        float val = x[i];
        out[i] = val / (1.0f + expf(-val));
    }
}

__global__ void sigmoid_kernel(const float* __restrict__ x,
                               float* __restrict__ out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        out[i] = 1.0f / (1.0f + expf(-x[i]));
    }
}

__global__ void mul_kernel(const float* __restrict__ a,
                           const float* __restrict__ b,
                           float* __restrict__ out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) out[i] = a[i] * b[i];
}

__global__ void add_kernel(const float* __restrict__ a,
                           const float* __restrict__ b,
                           float* __restrict__ out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) out[i] = a[i] + b[i];
}

__global__ void sgd_kernel(float* __restrict__ weights,
                           const float* __restrict__ grads,
                           float lr, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) weights[i] -= lr * grads[i];
}

__global__ void softmax_kernel(const float* __restrict__ x,
                               float* __restrict__ out,
                               int rows, int cols) {
    int row = blockIdx.x;
    if (row >= rows) return;

    const float* in = x + row * cols;
    float* o = out + row * cols;

    // Find max for numerical stability
    float max_val = -1e30f;
    for (int i = threadIdx.x; i < cols; i += blockDim.x)
        max_val = fmaxf(max_val, in[i]);

    // Warp reduction for max
    for (int offset = warpSize / 2; offset > 0; offset >>= 1)
        max_val = fmaxf(max_val, __shfl_down_sync(0xffffffff, max_val, offset));

    __shared__ float warp_vals[8];
    int lane = threadIdx.x % warpSize;
    int warp_id = threadIdx.x / warpSize;
    if (lane == 0) warp_vals[warp_id] = max_val;
    __syncthreads();

    if (warp_id == 0) {
        float val = (lane < (blockDim.x + warpSize - 1) / warpSize)
                        ? warp_vals[lane] : -1e30f;
        for (int offset = warpSize / 2; offset > 0; offset >>= 1)
            val = fmaxf(val, __shfl_down_sync(0xffffffff, val, offset));
        if (lane == 0) warp_vals[0] = val;
    }
    __syncthreads();
    float s_max = warp_vals[0];

    // Sum exp
    float sum = 0.0f;
    for (int i = threadIdx.x; i < cols; i += blockDim.x)
        sum += expf(in[i] - s_max);

    // Warp + block reduction for sum
    for (int offset = warpSize / 2; offset > 0; offset >>= 1)
        sum += __shfl_down_sync(0xffffffff, sum, offset);

    if (lane == 0) warp_vals[warp_id] = sum;
    __syncthreads();

    if (warp_id == 0) {
        float val = (lane < (blockDim.x + warpSize - 1) / warpSize)
                        ? warp_vals[lane] : 0.0f;
        for (int offset = warpSize / 2; offset > 0; offset >>= 1)
            val += __shfl_down_sync(0xffffffff, val, offset);
        if (lane == 0) warp_vals[0] = val;
    }
    __syncthreads();
    float s_sum = warp_vals[0];

    float inv_sum = 1.0f / s_sum;
    for (int i = threadIdx.x; i < cols; i += blockDim.x)
        o[i] = expf(in[i] - s_max) * inv_sum;
}

// Cross-entropy kernel: computes per-row loss into a device buffer
__global__ void cross_entropy_kernel(const float* __restrict__ logits,
                                     const uint8_t* __restrict__ targets,
                                     float* __restrict__ losses,
                                     int seq_len, int vocab) {
    int s = blockIdx.x;
    if (s >= seq_len) return;

    const float* row = logits + s * vocab;
    int target = static_cast<int>(targets[s]);

    // One thread per row (simple version; good enough for typical seq_len)
    if (threadIdx.x == 0) {
        float max_val = row[0];
        for (int v = 1; v < vocab; ++v)
            max_val = fmaxf(max_val, row[v]);

        float sum_exp = 0.0f;
        for (int v = 0; v < vocab; ++v)
            sum_exp += expf(row[v] - max_val);

        float log_prob = (row[target] - max_val) - logf(sum_exp);
        losses[s] = -log_prob;
    }
}

// ----------------------------------------------------------------
// Init / Shutdown
// ----------------------------------------------------------------

bool CUDABackend::init() {
    if (initialized_) return true;

    int device_count = 0;
    CUDA_CHECK_BOOL(cudaGetDeviceCount(&device_count));
    if (device_count == 0) return false;

    device_id_ = 0;
    CUDA_CHECK_BOOL(cudaSetDevice(device_id_));

    if (g_cublas == nullptr) {
        cublasStatus_t status = cublasCreate(&g_cublas);
        if (status != CUBLAS_STATUS_SUCCESS) {
            fprintf(stderr, "cuBLAS init failed: %d\n", static_cast<int>(status));
            return false;
        }
    }

    initialized_ = true;
    return true;
}

void CUDABackend::shutdown() {
    if (!initialized_) return;
    if (g_cublas) {
        cublasDestroy(g_cublas);
        g_cublas = nullptr;
    }
    initialized_ = false;
}

// ----------------------------------------------------------------
// Device info
// ----------------------------------------------------------------

std::string CUDABackend::device_name() const {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device_id_) == cudaSuccess)
        return std::string(prop.name);
    return "Unknown CUDA Device";
}

size_t CUDABackend::total_memory() const {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device_id_) == cudaSuccess)
        return prop.totalGlobalMem;
    return 0;
}

size_t CUDABackend::available_memory() const {
    size_t free_mem = 0, total_mem = 0;
    cudaSetDevice(device_id_);
    if (cudaMemGetInfo(&free_mem, &total_mem) == cudaSuccess)
        return free_mem;
    return 0;
}

// ----------------------------------------------------------------
// Memory management
// ----------------------------------------------------------------

void* CUDABackend::alloc(size_t bytes) {
    void* ptr = nullptr;
    cudaError_t err = cudaMalloc(&ptr, bytes);
    if (err != cudaSuccess) {
        fprintf(stderr, "cudaMalloc(%zu) failed: %s\n",
                bytes, cudaGetErrorString(err));
        return nullptr;
    }
    return ptr;
}

void CUDABackend::free(void* ptr) {
    if (ptr) cudaFree(ptr);
}

void CUDABackend::upload(void* dst, const float* src, size_t count) {
    cudaMemcpy(dst, src, count * sizeof(float), cudaMemcpyHostToDevice);
}

void CUDABackend::download(float* dst, const void* src, size_t count) {
    cudaMemcpy(dst, src, count * sizeof(float), cudaMemcpyDeviceToHost);
}

// ----------------------------------------------------------------
// Matrix multiply via cuBLAS: C = A @ B^T
// A: [M, K]   B: [N, K]   C: [M, N]
// cuBLAS is column-major, so we compute C^T = B * A^T in col-major
// ----------------------------------------------------------------

void CUDABackend::matmul(const void* A, const void* B, void* C,
                         int M, int N, int K) {
    float alpha = 1.0f, beta = 0.0f;
    // Row-major A[M,K] @ B[N,K]^T = C[M,N]
    // In column-major terms: C^T[N,M] = B[N,K] * A^T[K,M]
    // cublasSgemm(handle, transa, transb, m, n, k, ...)
    // computes C_col = alpha * op(A_col) * op(B_col) + beta * C_col
    // We want: C_col[N,M] = B_col[K,N]^T * A_col[K,M]
    cublasStatus_t status = cublasSgemm(
        g_cublas,
        CUBLAS_OP_T,    // op(A_col) = B^T -> reading B as col-major [K,N], transpose to [N,K]...
        CUBLAS_OP_N,    // op(B_col) = A   -> reading A as col-major [K,M]
        N, M, K,
        &alpha,
        static_cast<const float*>(B), K,   // B stored row-major [N,K] = col-major with lda=K
        static_cast<const float*>(A), K,   // A stored row-major [M,K] = col-major with lda=K
        &beta,
        static_cast<float*>(C), N          // C stored row-major [M,N] = col-major with ldc=N
    );
    if (status != CUBLAS_STATUS_SUCCESS) {
        fprintf(stderr, "cuBLAS sgemm failed: %d\n", static_cast<int>(status));
    }
}

// ----------------------------------------------------------------
// Kernel dispatch wrappers
// ----------------------------------------------------------------

void CUDABackend::rms_norm(const void* x, const void* w, void* out,
                           int rows, int cols) {
    int threads = std::min(kBlockSize, cols);
    rms_norm_kernel<<<rows, threads>>>(
        static_cast<const float*>(x),
        static_cast<const float*>(w),
        static_cast<float*>(out),
        rows, cols);
}

void CUDABackend::silu(const void* x, void* out, int n) {
    silu_kernel<<<grid_size(n), kBlockSize>>>(
        static_cast<const float*>(x),
        static_cast<float*>(out), n);
}

void CUDABackend::sigmoid(const void* x, void* out, int n) {
    sigmoid_kernel<<<grid_size(n), kBlockSize>>>(
        static_cast<const float*>(x),
        static_cast<float*>(out), n);
}

void CUDABackend::mul(const void* a, const void* b, void* out, int n) {
    mul_kernel<<<grid_size(n), kBlockSize>>>(
        static_cast<const float*>(a),
        static_cast<const float*>(b),
        static_cast<float*>(out), n);
}

void CUDABackend::add(const void* a, const void* b, void* out, int n) {
    add_kernel<<<grid_size(n), kBlockSize>>>(
        static_cast<const float*>(a),
        static_cast<const float*>(b),
        static_cast<float*>(out), n);
}

void CUDABackend::softmax(const void* x, void* out, int rows, int cols) {
    int threads = std::min(kBlockSize, cols);
    softmax_kernel<<<rows, threads>>>(
        static_cast<const float*>(x),
        static_cast<float*>(out),
        rows, cols);
}

float CUDABackend::cross_entropy(const void* logits, const uint8_t* targets,
                                 int seq_len, int vocab) {
    // Allocate device buffer for per-row losses
    float* d_losses = nullptr;
    cudaMalloc(&d_losses, seq_len * sizeof(float));

    // Upload targets to device
    uint8_t* d_targets = nullptr;
    cudaMalloc(&d_targets, seq_len * sizeof(uint8_t));
    cudaMemcpy(d_targets, targets, seq_len * sizeof(uint8_t),
               cudaMemcpyHostToDevice);

    cross_entropy_kernel<<<seq_len, 1>>>(
        static_cast<const float*>(logits),
        d_targets, d_losses, seq_len, vocab);

    // Download losses and average on host
    std::vector<float> h_losses(seq_len);
    cudaMemcpy(h_losses.data(), d_losses, seq_len * sizeof(float),
               cudaMemcpyDeviceToHost);

    cudaFree(d_losses);
    cudaFree(d_targets);

    double total = 0.0;
    for (int i = 0; i < seq_len; ++i)
        total += static_cast<double>(h_losses[i]);

    return static_cast<float>(total / static_cast<double>(seq_len));
}

void CUDABackend::topk(const void* scores, int* indices, float* values,
                       int n, int k) {
    // Download scores to host and do top-k on CPU
    // (GPU top-k is complex; for typical n this is fine)
    std::vector<float> h_scores(n);
    cudaMemcpy(h_scores.data(), scores, n * sizeof(float),
               cudaMemcpyDeviceToHost);

    std::vector<int> idx(n);
    std::iota(idx.begin(), idx.end(), 0);

    int actual_k = std::min(k, n);
    std::partial_sort(idx.begin(), idx.begin() + actual_k, idx.end(),
                      [&h_scores](int a, int b) {
                          return h_scores[a] > h_scores[b];
                      });

    for (int i = 0; i < actual_k; ++i) {
        indices[i] = idx[i];
        values[i] = h_scores[idx[i]];
    }
}

void CUDABackend::sgd_update(void* weights, const void* grads,
                             float lr, int n) {
    sgd_kernel<<<grid_size(n), kBlockSize>>>(
        static_cast<float*>(weights),
        static_cast<const float*>(grads),
        lr, n);
}

void CUDABackend::sync() {
    cudaDeviceSynchronize();
}

} // namespace flow::miner

#endif // FLOWCOIN_USE_CUDA
