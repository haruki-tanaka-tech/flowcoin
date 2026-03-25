#ifdef FLOWCOIN_USE_METAL
#include "backend_metal.h"
#include "backend_cpu.h"

#import <Metal/Metal.h>
#import <MetalPerformanceShaders/MetalPerformanceShaders.h>
#import <Foundation/Foundation.h>

#include <cstring>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>

namespace flow::miner {

// ----------------------------------------------------------------
// Metal compute shader source (embedded)
// ----------------------------------------------------------------

static const char* kMetalShaderSource = R"metal(
#include <metal_stdlib>
using namespace metal;

kernel void silu_kernel(device const float* x [[buffer(0)]],
                        device float* out [[buffer(1)]],
                        constant int& n [[buffer(2)]],
                        uint idx [[thread_position_in_grid]]) {
    if (idx >= uint(n)) return;
    float val = x[idx];
    out[idx] = val / (1.0f + exp(-val));
}

kernel void sigmoid_kernel(device const float* x [[buffer(0)]],
                           device float* out [[buffer(1)]],
                           constant int& n [[buffer(2)]],
                           uint idx [[thread_position_in_grid]]) {
    if (idx >= uint(n)) return;
    out[idx] = 1.0f / (1.0f + exp(-x[idx]));
}

kernel void mul_kernel(device const float* a [[buffer(0)]],
                       device const float* b [[buffer(1)]],
                       device float* out [[buffer(2)]],
                       constant int& n [[buffer(3)]],
                       uint idx [[thread_position_in_grid]]) {
    if (idx >= uint(n)) return;
    out[idx] = a[idx] * b[idx];
}

kernel void add_kernel(device const float* a [[buffer(0)]],
                       device const float* b [[buffer(1)]],
                       device float* out [[buffer(2)]],
                       constant int& n [[buffer(3)]],
                       uint idx [[thread_position_in_grid]]) {
    if (idx >= uint(n)) return;
    out[idx] = a[idx] + b[idx];
}

kernel void sgd_kernel(device float* weights [[buffer(0)]],
                       device const float* grads [[buffer(1)]],
                       constant float& lr [[buffer(2)]],
                       constant int& n [[buffer(3)]],
                       uint idx [[thread_position_in_grid]]) {
    if (idx >= uint(n)) return;
    weights[idx] -= lr * grads[idx];
}

kernel void rms_norm_kernel(device const float* x [[buffer(0)]],
                            device const float* w [[buffer(1)]],
                            device float* out [[buffer(2)]],
                            constant int& cols [[buffer(3)]],
                            uint row [[threadgroup_position_in_grid]],
                            uint tid [[thread_index_in_threadgroup]],
                            uint tg_size [[threads_per_threadgroup]]) {
    device const float* x_row = x + row * cols;
    device float* out_row = out + row * cols;

    // Compute sum of squares
    float sum_sq = 0.0f;
    for (int i = int(tid); i < cols; i += int(tg_size)) {
        sum_sq += x_row[i] * x_row[i];
    }

    // Threadgroup reduction via shared memory
    threadgroup float shared[256];
    shared[tid] = sum_sq;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint s = tg_size / 2; s > 0; s >>= 1) {
        if (tid < s) shared[tid] += shared[tid + s];
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    float rms_inv = rsqrt(shared[0] / float(cols) + 1e-6f);

    for (int i = int(tid); i < cols; i += int(tg_size)) {
        out_row[i] = x_row[i] * w[i] * rms_inv;
    }
}
)metal";

// ----------------------------------------------------------------
// Metal context (Objective-C objects held as opaque pointers)
// ----------------------------------------------------------------

struct MetalContext {
    id<MTLDevice> device;
    id<MTLCommandQueue> queue;
    id<MTLLibrary> library;
    id<MTLComputePipelineState> silu_pipeline;
    id<MTLComputePipelineState> sigmoid_pipeline;
    id<MTLComputePipelineState> mul_pipeline;
    id<MTLComputePipelineState> add_pipeline;
    id<MTLComputePipelineState> sgd_pipeline;
    id<MTLComputePipelineState> rms_norm_pipeline;
    CPUBackend* cpu_fallback;
};

// ----------------------------------------------------------------
// Init / Shutdown
// ----------------------------------------------------------------

static id<MTLComputePipelineState> make_pipeline(id<MTLDevice> device,
                                                  id<MTLLibrary> library,
                                                  NSString* name) {
    id<MTLFunction> fn = [library newFunctionWithName:name];
    if (!fn) {
        fprintf(stderr, "Metal: function '%s' not found\n",
                [name UTF8String]);
        return nil;
    }
    NSError* error = nil;
    id<MTLComputePipelineState> pipeline =
        [device newComputePipelineStateWithFunction:fn error:&error];
    if (error) {
        fprintf(stderr, "Metal: pipeline error: %s\n",
                [[error localizedDescription] UTF8String]);
        return nil;
    }
    return pipeline;
}

bool MetalBackend::init() {
    if (initialized_) return true;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            fprintf(stderr, "Metal: no device available\n");
            return false;
        }

        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (!queue) {
            fprintf(stderr, "Metal: failed to create command queue\n");
            return false;
        }

        // Compile shader library from source
        NSString* src = [NSString stringWithUTF8String:kMetalShaderSource];
        NSError* error = nil;
        id<MTLLibrary> library = [device newLibraryWithSource:src
                                                     options:nil
                                                       error:&error];
        if (error) {
            fprintf(stderr, "Metal: shader compile error: %s\n",
                    [[error localizedDescription] UTF8String]);
            return false;
        }

        ctx_ = new MetalContext();
        ctx_->device = device;
        ctx_->queue = queue;
        ctx_->library = library;

        ctx_->silu_pipeline = make_pipeline(device, library, @"silu_kernel");
        ctx_->sigmoid_pipeline = make_pipeline(device, library, @"sigmoid_kernel");
        ctx_->mul_pipeline = make_pipeline(device, library, @"mul_kernel");
        ctx_->add_pipeline = make_pipeline(device, library, @"add_kernel");
        ctx_->sgd_pipeline = make_pipeline(device, library, @"sgd_kernel");
        ctx_->rms_norm_pipeline = make_pipeline(device, library, @"rms_norm_kernel");

        ctx_->cpu_fallback = new CPUBackend();
        ctx_->cpu_fallback->init();

        initialized_ = true;
        return true;
    }
}

void MetalBackend::shutdown() {
    if (!initialized_) return;
    if (ctx_) {
        delete ctx_->cpu_fallback;
        delete ctx_;
        ctx_ = nullptr;
    }
    initialized_ = false;
}

// ----------------------------------------------------------------
// Device info
// ----------------------------------------------------------------

std::string MetalBackend::device_name() const {
    if (!ctx_) return "Unknown";
    @autoreleasepool {
        return std::string([[ctx_->device name] UTF8String]);
    }
}

size_t MetalBackend::total_memory() const {
    if (!ctx_) return 0;
    // recommendedMaxWorkingSetSize is available on macOS
    return static_cast<size_t>([ctx_->device recommendedMaxWorkingSetSize]);
}

size_t MetalBackend::available_memory() const {
    // Metal does not provide a direct free-memory query
    return total_memory();
}

// ----------------------------------------------------------------
// Memory management via MTLBuffer (shared memory mode)
// ----------------------------------------------------------------

struct MetalAlloc {
    id<MTLBuffer> buffer;
    size_t size;
};

void* MetalBackend::alloc(size_t bytes) {
    if (!ctx_) return nullptr;
    @autoreleasepool {
        id<MTLBuffer> buffer = [ctx_->device
            newBufferWithLength:bytes
                       options:MTLResourceStorageModeShared];
        if (!buffer) return nullptr;
        auto* handle = new MetalAlloc{buffer, bytes};
        return static_cast<void*>(handle);
    }
}

void MetalBackend::free(void* ptr) {
    if (!ptr) return;
    auto* handle = static_cast<MetalAlloc*>(ptr);
    // ARC handles buffer release
    delete handle;
}

void MetalBackend::upload(void* dst, const float* src, size_t count) {
    auto* handle = static_cast<MetalAlloc*>(dst);
    std::memcpy([handle->buffer contents], src, count * sizeof(float));
}

void MetalBackend::download(float* dst, const void* src, size_t count) {
    auto* handle = static_cast<const MetalAlloc*>(src);
    std::memcpy(dst, [handle->buffer contents], count * sizeof(float));
}

// ----------------------------------------------------------------
// Helper: dispatch a simple element-wise kernel
// ----------------------------------------------------------------

static void dispatch_elementwise(MetalContext* ctx,
                                 id<MTLComputePipelineState> pipeline,
                                 id<MTLBuffer> buf0,
                                 id<MTLBuffer> buf1,
                                 int n) {
    @autoreleasepool {
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:buf0 offset:0 atIndex:0];
        [enc setBuffer:buf1 offset:0 atIndex:1];
        [enc setBytes:&n length:sizeof(int) atIndex:2];

        NSUInteger tg_size = pipeline.maxTotalThreadsPerThreadgroup;
        if (tg_size > 256) tg_size = 256;
        MTLSize grid = MTLSizeMake(n, 1, 1);
        MTLSize group = MTLSizeMake(tg_size, 1, 1);
        [enc dispatchThreads:grid threadsPerThreadgroup:group];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];
    }
}

static void dispatch_binary(MetalContext* ctx,
                             id<MTLComputePipelineState> pipeline,
                             id<MTLBuffer> buf0,
                             id<MTLBuffer> buf1,
                             id<MTLBuffer> buf2,
                             int n) {
    @autoreleasepool {
        id<MTLCommandBuffer> cmd = [ctx->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:buf0 offset:0 atIndex:0];
        [enc setBuffer:buf1 offset:0 atIndex:1];
        [enc setBuffer:buf2 offset:0 atIndex:2];
        [enc setBytes:&n length:sizeof(int) atIndex:3];

        NSUInteger tg_size = pipeline.maxTotalThreadsPerThreadgroup;
        if (tg_size > 256) tg_size = 256;
        MTLSize grid = MTLSizeMake(n, 1, 1);
        MTLSize group = MTLSizeMake(tg_size, 1, 1);
        [enc dispatchThreads:grid threadsPerThreadgroup:group];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];
    }
}

// ----------------------------------------------------------------
// Compute operations
// ----------------------------------------------------------------

static id<MTLBuffer> mtl_buf(const void* handle) {
    return static_cast<const MetalAlloc*>(handle)->buffer;
}

static float* mtl_fptr(void* handle) {
    return static_cast<float*>([static_cast<MetalAlloc*>(handle)->buffer contents]);
}

static const float* mtl_cfptr(const void* handle) {
    return static_cast<const float*>(
        [static_cast<const MetalAlloc*>(handle)->buffer contents]);
}

void MetalBackend::matmul(const void* A, const void* B, void* C,
                          int M, int N, int K) {
    // Use MPS for matrix multiply
    @autoreleasepool {
        MPSMatrixDescriptor* descA = [MPSMatrixDescriptor
            matrixDescriptorWithRows:M columns:K rowBytes:K * sizeof(float)
                            dataType:MPSDataTypeFloat32];
        MPSMatrixDescriptor* descB = [MPSMatrixDescriptor
            matrixDescriptorWithRows:N columns:K rowBytes:K * sizeof(float)
                            dataType:MPSDataTypeFloat32];
        MPSMatrixDescriptor* descC = [MPSMatrixDescriptor
            matrixDescriptorWithRows:M columns:N rowBytes:N * sizeof(float)
                            dataType:MPSDataTypeFloat32];

        MPSMatrix* matA = [[MPSMatrix alloc] initWithBuffer:mtl_buf(A)
                                                 descriptor:descA];
        MPSMatrix* matB = [[MPSMatrix alloc] initWithBuffer:mtl_buf(B)
                                                 descriptor:descB];
        MPSMatrix* matC = [[MPSMatrix alloc] initWithBuffer:mtl_buf(C)
                                                 descriptor:descC];

        // C = A * B^T
        MPSMatrixMultiplication* mul =
            [[MPSMatrixMultiplication alloc] initWithDevice:ctx_->device
                                             transposeLeft:NO
                                            transposeRight:YES
                                                resultRows:M
                                             resultColumns:N
                                           interiorColumns:K
                                                     alpha:1.0
                                                      beta:0.0];

        id<MTLCommandBuffer> cmd = [ctx_->queue commandBuffer];
        [mul encodeToCommandBuffer:cmd leftMatrix:matA rightMatrix:matB
                      resultMatrix:matC];
        [cmd commit];
        [cmd waitUntilCompleted];
    }
}

void MetalBackend::rms_norm(const void* x, const void* w, void* out,
                            int rows, int cols) {
    @autoreleasepool {
        id<MTLCommandBuffer> cmd = [ctx_->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx_->rms_norm_pipeline];
        [enc setBuffer:mtl_buf(x) offset:0 atIndex:0];
        [enc setBuffer:mtl_buf(w) offset:0 atIndex:1];
        [enc setBuffer:mtl_buf(out) offset:0 atIndex:2];
        [enc setBytes:&cols length:sizeof(int) atIndex:3];

        NSUInteger tg_size = ctx_->rms_norm_pipeline.maxTotalThreadsPerThreadgroup;
        if (tg_size > 256) tg_size = 256;
        MTLSize grid = MTLSizeMake(tg_size * rows, 1, 1);
        MTLSize group = MTLSizeMake(tg_size, 1, 1);
        [enc dispatchThreads:grid threadsPerThreadgroup:group];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];
    }
}

void MetalBackend::silu(const void* x, void* out, int n) {
    dispatch_elementwise(ctx_, ctx_->silu_pipeline,
                         mtl_buf(x), mtl_buf(out), n);
}

void MetalBackend::sigmoid(const void* x, void* out, int n) {
    dispatch_elementwise(ctx_, ctx_->sigmoid_pipeline,
                         mtl_buf(x), mtl_buf(out), n);
}

void MetalBackend::mul(const void* a, const void* b, void* out, int n) {
    dispatch_binary(ctx_, ctx_->mul_pipeline,
                    mtl_buf(a), mtl_buf(b), mtl_buf(out), n);
}

void MetalBackend::add(const void* a, const void* b, void* out, int n) {
    dispatch_binary(ctx_, ctx_->add_pipeline,
                    mtl_buf(a), mtl_buf(b), mtl_buf(out), n);
}

void MetalBackend::softmax(const void* x, void* out, int rows, int cols) {
    // CPU fallback for softmax
    ctx_->cpu_fallback->softmax(mtl_cfptr(x), mtl_fptr(out), rows, cols);
}

float MetalBackend::cross_entropy(const void* logits, const uint8_t* targets,
                                  int seq_len, int vocab) {
    return ctx_->cpu_fallback->cross_entropy(mtl_cfptr(logits), targets,
                                             seq_len, vocab);
}

void MetalBackend::topk(const void* scores, int* indices, float* values,
                        int n, int k) {
    ctx_->cpu_fallback->topk(mtl_cfptr(scores), indices, values, n, k);
}

void MetalBackend::sgd_update(void* weights, const void* grads,
                              float lr, int n) {
    @autoreleasepool {
        id<MTLCommandBuffer> cmd = [ctx_->queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:ctx_->sgd_pipeline];
        [enc setBuffer:mtl_buf(weights) offset:0 atIndex:0];
        [enc setBuffer:mtl_buf(grads) offset:0 atIndex:1];
        [enc setBytes:&lr length:sizeof(float) atIndex:2];
        [enc setBytes:&n length:sizeof(int) atIndex:3];

        NSUInteger tg_size = ctx_->sgd_pipeline.maxTotalThreadsPerThreadgroup;
        if (tg_size > 256) tg_size = 256;
        MTLSize grid = MTLSizeMake(n, 1, 1);
        MTLSize group = MTLSizeMake(tg_size, 1, 1);
        [enc dispatchThreads:grid threadsPerThreadgroup:group];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];
    }
}

void MetalBackend::sync() {
    // All dispatches above already wait until completed
}

} // namespace flow::miner

#endif // FLOWCOIN_USE_METAL
