#pragma once
#ifdef FLOWCOIN_USE_CUDA

#include <cstddef>
#include <cstdint>

namespace flow::miner::cuda {

bool init();
void shutdown();
const char* device_name();
size_t total_memory();

// GPU memory management
float* alloc(size_t count);
void free(float* ptr);
void upload(float* gpu, const float* cpu, size_t count);
void download(float* cpu, const float* gpu, size_t count);
void zero(float* gpu, size_t count);

// Matrix multiply: C = A @ B^T  (A:[M,K], B:[N,K], C:[M,N])
void matmul(const float* A, const float* B, float* C, int M, int N, int K);

// Element-wise operations
void silu(const float* x, float* out, int n);
void sigmoid(const float* x, float* out, int n);
void mul(const float* a, const float* b, float* out, int n);
void add(const float* a, const float* b, float* out, int n);
void add_bias(const float* x, const float* bias, float* out, int rows, int cols);
void rms_norm(const float* x, const float* w, float* out, int rows, int cols);
void softmax(const float* x, float* out, int rows, int cols);
void sgd_update(float* w, const float* grad, float lr, int n);

// Cross-entropy loss (returns scalar on CPU)
float cross_entropy(const float* logits, const uint8_t* targets_gpu, int seq_len, int vocab);

// Embedding lookup: out[t] = emb[tokens[t]]
void get_rows(const float* emb, const int32_t* tokens_gpu, float* out, int n_tokens, int d_model, int vocab);

void sync();

// Raw memory ops (avoid including cuda_runtime.h in .cpp files)
void* raw_alloc(size_t bytes);
void raw_free(void* ptr);
void raw_upload(void* gpu, const void* cpu, size_t bytes);
void raw_download(void* cpu, const void* gpu, size_t bytes);

} // namespace flow::miner::cuda

#endif
