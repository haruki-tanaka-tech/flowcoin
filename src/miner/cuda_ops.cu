#ifdef FLOWCOIN_USE_CUDA
#include "cuda_ops.h"
#include <cuda_runtime.h>
#include <cublas_v2.h>
#include <cstdio>
#include <cmath>
#include <algorithm>

namespace flow::miner::cuda {

static cublasHandle_t g_cublas = nullptr;
static int g_device = 0;
static char g_device_name[256] = "Unknown";

bool init() {
    cudaError_t err = cudaSetDevice(0);
    if (err != cudaSuccess) return false;

    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    snprintf(g_device_name, sizeof(g_device_name), "%s", prop.name);

    cublasStatus_t st = cublasCreate(&g_cublas);
    if (st != CUBLAS_STATUS_SUCCESS) return false;

    // Use TF32 for speed on Ampere+
    cublasSetMathMode(g_cublas, CUBLAS_TF32_TENSOR_OP_MATH);

    return true;
}

void shutdown() {
    if (g_cublas) { cublasDestroy(g_cublas); g_cublas = nullptr; }
}

const char* device_name() { return g_device_name; }

size_t total_memory() {
    size_t free_mem, total_mem;
    cudaMemGetInfo(&free_mem, &total_mem);
    return total_mem;
}

float* alloc(size_t count) {
    float* ptr = nullptr;
    cudaMalloc(&ptr, count * sizeof(float));
    return ptr;
}

void free(float* ptr) { if (ptr) cudaFree(ptr); }
void upload(float* gpu, const float* cpu, size_t count) { cudaMemcpy(gpu, cpu, count * sizeof(float), cudaMemcpyHostToDevice); }
void download(float* cpu, const float* gpu, size_t count) { cudaMemcpy(cpu, gpu, count * sizeof(float), cudaMemcpyDeviceToHost); }
void zero(float* gpu, size_t count) { cudaMemset(gpu, 0, count * sizeof(float)); }
void sync() { cudaDeviceSynchronize(); }

// cuBLAS matmul: C = A @ B^T
void matmul(const float* A, const float* B, float* C, int M, int N, int K) {
    float alpha = 1.0f, beta = 0.0f;
    // cuBLAS is column-major: C^T = B * A^T → swap A and B
    cublasSgemm(g_cublas, CUBLAS_OP_T, CUBLAS_OP_N,
                N, M, K, &alpha, B, K, A, K, &beta, C, N);
}

// ═══ CUDA Kernels ═══

__global__ void silu_kernel(const float* x, float* out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) { float v = x[i]; out[i] = v / (1.0f + expf(-v)); }
}

__global__ void sigmoid_kernel(const float* x, float* out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) out[i] = 1.0f / (1.0f + expf(-x[i]));
}

__global__ void mul_kernel(const float* a, const float* b, float* out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) out[i] = a[i] * b[i];
}

__global__ void add_kernel(const float* a, const float* b, float* out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) out[i] = a[i] + b[i];
}

__global__ void add_bias_kernel(const float* x, const float* bias, float* out, int rows, int cols) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < rows * cols) {
        out[idx] = x[idx] + bias[idx % cols];
    }
}

__global__ void sgd_kernel(float* w, const float* g, float lr, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) w[i] -= lr * g[i];
}

__global__ void rms_norm_kernel(const float* x, const float* w, float* out, int rows, int cols) {
    int row = blockIdx.x;
    if (row >= rows) return;

    extern __shared__ float sdata[];
    const float* xr = x + row * cols;
    float* or_ = out + row * cols;

    float sum_sq = 0.0f;
    for (int i = threadIdx.x; i < cols; i += blockDim.x)
        sum_sq += xr[i] * xr[i];

    sdata[threadIdx.x] = sum_sq;
    __syncthreads();
    for (int s = blockDim.x / 2; s > 0; s >>= 1) {
        if (threadIdx.x < s) sdata[threadIdx.x] += sdata[threadIdx.x + s];
        __syncthreads();
    }

    float rms = rsqrtf(sdata[0] / cols + 1e-6f);
    for (int i = threadIdx.x; i < cols; i += blockDim.x)
        or_[i] = xr[i] * w[i] * rms;
}

__global__ void softmax_kernel(const float* x, float* out, int rows, int cols) {
    int row = blockIdx.x;
    if (row >= rows) return;

    extern __shared__ float sdata[];
    const float* xr = x + row * cols;
    float* or_ = out + row * cols;

    float max_val = -1e30f;
    for (int i = threadIdx.x; i < cols; i += blockDim.x)
        max_val = fmaxf(max_val, xr[i]);
    sdata[threadIdx.x] = max_val;
    __syncthreads();
    for (int s = blockDim.x / 2; s > 0; s >>= 1) {
        if (threadIdx.x < s) sdata[threadIdx.x] = fmaxf(sdata[threadIdx.x], sdata[threadIdx.x + s]);
        __syncthreads();
    }
    max_val = sdata[0];

    float sum = 0.0f;
    for (int i = threadIdx.x; i < cols; i += blockDim.x)
        sum += expf(xr[i] - max_val);
    sdata[threadIdx.x] = sum;
    __syncthreads();
    for (int s = blockDim.x / 2; s > 0; s >>= 1) {
        if (threadIdx.x < s) sdata[threadIdx.x] += sdata[threadIdx.x + s];
        __syncthreads();
    }
    sum = sdata[0];

    for (int i = threadIdx.x; i < cols; i += blockDim.x)
        or_[i] = expf(xr[i] - max_val) / sum;
}

__global__ void cross_entropy_kernel(const float* logits, const uint8_t* targets,
                                       float* losses, int seq_len, int vocab) {
    int t = blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= seq_len) return;

    const float* row = logits + t * vocab;
    int tgt = targets[t];

    // log_softmax(logits[tgt])
    float max_val = -1e30f;
    for (int v = 0; v < vocab; v++) max_val = fmaxf(max_val, row[v]);

    float sum = 0.0f;
    for (int v = 0; v < vocab; v++) sum += expf(row[v] - max_val);

    losses[t] = -(row[tgt] - max_val - logf(sum));
}

__global__ void get_rows_kernel(const float* emb, const int32_t* tokens, float* out,
                                  int n_tokens, int d_model) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int total = n_tokens * d_model;
    if (idx < total) {
        int t = idx / d_model;
        int d = idx % d_model;
        out[idx] = emb[tokens[t] * d_model + d];
    }
}

// Wrapper functions
void silu(const float* x, float* out, int n) { silu_kernel<<<(n+255)/256, 256>>>(x, out, n); }
void sigmoid(const float* x, float* out, int n) { sigmoid_kernel<<<(n+255)/256, 256>>>(x, out, n); }
void mul(const float* a, const float* b, float* out, int n) { mul_kernel<<<(n+255)/256, 256>>>(a, b, out, n); }
void add(const float* a, const float* b, float* out, int n) { add_kernel<<<(n+255)/256, 256>>>(a, b, out, n); }
void add_bias(const float* x, const float* bias, float* out, int rows, int cols) {
    int n = rows * cols;
    add_bias_kernel<<<(n+255)/256, 256>>>(x, bias, out, rows, cols);
}
void sgd_update(float* w, const float* g, float lr, int n) { sgd_kernel<<<(n+255)/256, 256>>>(w, g, lr, n); }
void rms_norm(const float* x, const float* w, float* out, int rows, int cols) {
    int threads = std::min(256, cols);
    rms_norm_kernel<<<rows, threads, threads * sizeof(float)>>>(x, w, out, rows, cols);
}
void softmax(const float* x, float* out, int rows, int cols) {
    int threads = std::min(256, cols);
    softmax_kernel<<<rows, threads, threads * sizeof(float)>>>(x, out, rows, cols);
}

float cross_entropy(const float* logits, const uint8_t* targets_gpu, int seq_len, int vocab) {
    float* d_losses = alloc(seq_len);
    cross_entropy_kernel<<<(seq_len+255)/256, 256>>>(logits, targets_gpu, d_losses, seq_len, vocab);

    // Sum on GPU using cublas
    float result = 0;
    float* h_losses = new float[seq_len];
    download(h_losses, d_losses, seq_len);
    for (int i = 0; i < seq_len; i++) result += h_losses[i];
    result /= seq_len;
    delete[] h_losses;
    free(d_losses);
    return result;
}

void get_rows(const float* emb, const int32_t* tokens_gpu, float* out, int n_tokens, int d_model, int vocab) {
    int n = n_tokens * d_model;
    get_rows_kernel<<<(n+255)/256, 256>>>(emb, tokens_gpu, out, n_tokens, d_model);
}

void* raw_alloc(size_t bytes) { void* p = nullptr; cudaMalloc(&p, bytes); return p; }
void raw_free(void* ptr) { if (ptr) cudaFree(ptr); }
void raw_upload(void* gpu, const void* cpu, size_t bytes) { cudaMemcpy(gpu, cpu, bytes, cudaMemcpyHostToDevice); }
void raw_download(void* cpu, const void* gpu, size_t bytes) { cudaMemcpy(cpu, gpu, bytes, cudaMemcpyDeviceToHost); }

} // namespace flow::miner::cuda
#endif
