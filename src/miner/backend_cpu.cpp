#include "backend_cpu.h"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <functional>
#include <limits>

#ifdef _OPENMP
#include <omp.h>
#endif

#ifdef __linux__
#include <unistd.h>
#include <sys/sysinfo.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#include <mach/mach.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace flow::miner {

// ----------------------------------------------------------------
// Device info
// ----------------------------------------------------------------

std::string CPUBackend::device_name() const {
#ifdef __linux__
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("model name") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                std::string result = line.substr(pos + 1);
                // Trim leading whitespace
                size_t start = result.find_first_not_of(" \t");
                if (start != std::string::npos)
                    result = result.substr(start);
                return result;
            }
        }
    }
    return "Unknown CPU";
#elif defined(__APPLE__)
    char buf[256] = {};
    size_t len = sizeof(buf);
    if (sysctlbyname("machdep.cpu.brand_string", buf, &len, nullptr, 0) == 0)
        return std::string(buf);
    return "Apple CPU";
#elif defined(_WIN32)
    // Simplified — full implementation would read registry
    return "x86-64 CPU";
#else
    return "Unknown CPU";
#endif
}

size_t CPUBackend::total_memory() const {
#ifdef __linux__
    struct sysinfo si;
    if (sysinfo(&si) == 0)
        return static_cast<size_t>(si.totalram) * si.mem_unit;
    return 0;
#elif defined(__APPLE__)
    int64_t mem = 0;
    size_t len = sizeof(mem);
    sysctlbyname("hw.memsize", &mem, &len, nullptr, 0);
    return static_cast<size_t>(mem);
#elif defined(_WIN32)
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return static_cast<size_t>(ms.ullTotalPhys);
#else
    return 0;
#endif
}

size_t CPUBackend::available_memory() const {
#ifdef __linux__
    struct sysinfo si;
    if (sysinfo(&si) == 0)
        return static_cast<size_t>(si.freeram) * si.mem_unit;
    return 0;
#elif defined(__APPLE__)
    mach_port_t host = mach_host_self();
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(host, HOST_VM_INFO64,
                          reinterpret_cast<host_info64_t>(&vm_stat),
                          &count) == KERN_SUCCESS) {
        return static_cast<size_t>(vm_stat.free_count) * sysconf(_SC_PAGESIZE);
    }
    return 0;
#elif defined(_WIN32)
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return static_cast<size_t>(ms.ullAvailPhys);
#else
    return 0;
#endif
}

// ----------------------------------------------------------------
// Matrix multiply: C = A @ B^T
// A: [M, K]   B: [N, K]   C: [M, N]
// ----------------------------------------------------------------

void CPUBackend::matmul(const void* A, const void* B, void* C,
                        int M, int N, int K) {
    const float* a = static_cast<const float*>(A);
    const float* b = static_cast<const float*>(B);
    float* c = static_cast<float*>(C);

    #pragma omp parallel for schedule(dynamic)
    for (int i = 0; i < M; ++i) {
        const float* a_row = a + i * K;
        float* c_row = c + i * N;
        for (int j = 0; j < N; ++j) {
            const float* b_row = b + j * K;
            float sum = 0.0f;
            for (int p = 0; p < K; ++p) {
                sum += a_row[p] * b_row[p];
            }
            c_row[j] = sum;
        }
    }
}

// ----------------------------------------------------------------
// RMS Norm: out[r][c] = x[r][c] * w[c] / rms(x[r])
// ----------------------------------------------------------------

void CPUBackend::rms_norm(const void* x, const void* w, void* out,
                          int rows, int cols) {
    const float* xp = static_cast<const float*>(x);
    const float* wp = static_cast<const float*>(w);
    float* op = static_cast<float*>(out);

    #pragma omp parallel for
    for (int r = 0; r < rows; ++r) {
        const float* x_row = xp + r * cols;
        float* o_row = op + r * cols;

        float sum_sq = 0.0f;
        for (int c = 0; c < cols; ++c) {
            sum_sq += x_row[c] * x_row[c];
        }
        float rms_inv = 1.0f / std::sqrt(sum_sq / static_cast<float>(cols) + 1e-6f);

        for (int c = 0; c < cols; ++c) {
            o_row[c] = x_row[c] * wp[c] * rms_inv;
        }
    }
}

// ----------------------------------------------------------------
// SiLU: out[i] = x[i] * sigmoid(x[i]) = x[i] / (1 + exp(-x[i]))
// ----------------------------------------------------------------

void CPUBackend::silu(const void* x, void* out, int n) {
    const float* xp = static_cast<const float*>(x);
    float* op = static_cast<float*>(out);

    #pragma omp parallel for
    for (int i = 0; i < n; ++i) {
        float v = xp[i];
        op[i] = v / (1.0f + std::exp(-v));
    }
}

// ----------------------------------------------------------------
// Sigmoid: out[i] = 1 / (1 + exp(-x[i]))
// ----------------------------------------------------------------

void CPUBackend::sigmoid(const void* x, void* out, int n) {
    const float* xp = static_cast<const float*>(x);
    float* op = static_cast<float*>(out);

    #pragma omp parallel for
    for (int i = 0; i < n; ++i) {
        op[i] = 1.0f / (1.0f + std::exp(-xp[i]));
    }
}

// ----------------------------------------------------------------
// Element-wise multiply: out[i] = a[i] * b[i]
// ----------------------------------------------------------------

void CPUBackend::mul(const void* a, const void* b, void* out, int n) {
    const float* ap = static_cast<const float*>(a);
    const float* bp = static_cast<const float*>(b);
    float* op = static_cast<float*>(out);

    #pragma omp parallel for
    for (int i = 0; i < n; ++i) {
        op[i] = ap[i] * bp[i];
    }
}

// ----------------------------------------------------------------
// Element-wise add: out[i] = a[i] + b[i]
// ----------------------------------------------------------------

void CPUBackend::add(const void* a, const void* b, void* out, int n) {
    const float* ap = static_cast<const float*>(a);
    const float* bp = static_cast<const float*>(b);
    float* op = static_cast<float*>(out);

    #pragma omp parallel for
    for (int i = 0; i < n; ++i) {
        op[i] = ap[i] + bp[i];
    }
}

// ----------------------------------------------------------------
// Softmax per row: out[r][c] = exp(x[r][c]-max) / sum(exp(x[r]-max))
// ----------------------------------------------------------------

void CPUBackend::softmax(const void* x, void* out, int rows, int cols) {
    const float* xp = static_cast<const float*>(x);
    float* op = static_cast<float*>(out);

    #pragma omp parallel for
    for (int r = 0; r < rows; ++r) {
        const float* x_row = xp + r * cols;
        float* o_row = op + r * cols;

        // Find max for numerical stability
        float max_val = x_row[0];
        for (int c = 1; c < cols; ++c) {
            if (x_row[c] > max_val) max_val = x_row[c];
        }

        // Compute exp and sum
        float sum = 0.0f;
        for (int c = 0; c < cols; ++c) {
            o_row[c] = std::exp(x_row[c] - max_val);
            sum += o_row[c];
        }

        // Normalize
        float inv_sum = 1.0f / sum;
        for (int c = 0; c < cols; ++c) {
            o_row[c] *= inv_sum;
        }
    }
}

// ----------------------------------------------------------------
// Cross-entropy loss
// logits: [seq_len, vocab]   targets: [seq_len] (token indices)
// Returns average cross-entropy over sequence
// ----------------------------------------------------------------

float CPUBackend::cross_entropy(const void* logits, const uint8_t* targets,
                                int seq_len, int vocab) {
    const float* lp = static_cast<const float*>(logits);
    double total_loss = 0.0;

    for (int s = 0; s < seq_len; ++s) {
        const float* row = lp + s * vocab;
        int target = static_cast<int>(targets[s]);

        // Numerically stable log-softmax
        float max_val = row[0];
        for (int v = 1; v < vocab; ++v) {
            if (row[v] > max_val) max_val = row[v];
        }

        double log_sum_exp = 0.0;
        for (int v = 0; v < vocab; ++v) {
            log_sum_exp += std::exp(static_cast<double>(row[v] - max_val));
        }
        log_sum_exp = std::log(log_sum_exp);

        double log_prob = static_cast<double>(row[target] - max_val) - log_sum_exp;
        total_loss -= log_prob;
    }

    return static_cast<float>(total_loss / static_cast<double>(seq_len));
}

// ----------------------------------------------------------------
// Top-k: find the k largest elements in scores[0..n-1]
// Writes k indices and k values (sorted descending)
// ----------------------------------------------------------------

void CPUBackend::topk(const void* scores, int* indices, float* values,
                      int n, int k) {
    const float* sp = static_cast<const float*>(scores);

    // Build index array
    std::vector<int> idx(n);
    std::iota(idx.begin(), idx.end(), 0);

    // Partial sort to get top-k
    if (k < n) {
        std::partial_sort(idx.begin(), idx.begin() + k, idx.end(),
                          [sp](int a, int b) { return sp[a] > sp[b]; });
    } else {
        std::sort(idx.begin(), idx.end(),
                  [sp](int a, int b) { return sp[a] > sp[b]; });
        k = n;
    }

    for (int i = 0; i < k; ++i) {
        indices[i] = idx[i];
        values[i] = sp[idx[i]];
    }
}

// ----------------------------------------------------------------
// SGD update: weights[i] -= lr * grads[i]
// ----------------------------------------------------------------

void CPUBackend::sgd_update(void* weights, const void* grads, float lr, int n) {
    float* wp = static_cast<float*>(weights);
    const float* gp = static_cast<const float*>(grads);

    #pragma omp parallel for
    for (int i = 0; i < n; ++i) {
        wp[i] -= lr * gp[i];
    }
}

} // namespace flow::miner
