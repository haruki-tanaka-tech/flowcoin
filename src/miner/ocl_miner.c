/*
 * ocl_miner.c - OpenCL host-side code for Keccak-256d GPU mining.
 * Compiles the kernel at runtime from ocl_keccak.cl — no nvcc needed.
 */

#include "ocl_miner.h"
#include "keccak2.h"

#define CL_TARGET_OPENCL_VERSION 120

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ═══════════════════════════════════════════════════════════════════════
 * Load kernel source from .cl file at runtime
 * ═══════════════════════════════════════════════════════════════════════ */

static char *load_kernel_source(void) {
    const char *paths[] = {
        "ocl_keccak.cl",
        "/usr/share/flowcoin/ocl_keccak.cl",
        "/usr/local/share/flowcoin/ocl_keccak.cl",
        NULL
    };

    /* Try the binary's directory first via /proc/self/exe */
    char exe_dir[512] = {0};
    char exe_cl[600] = {0};
    ssize_t len = readlink("/proc/self/exe", exe_dir, sizeof(exe_dir) - 1);
    if (len > 0) {
        exe_dir[len] = '\0';
        /* Strip binary name to get directory */
        char *slash = strrchr(exe_dir, '/');
        if (slash) {
            *(slash + 1) = '\0';
            snprintf(exe_cl, sizeof(exe_cl), "%socl_keccak.cl", exe_dir);
            FILE *f = fopen(exe_cl, "r");
            if (f) {
                fseek(f, 0, SEEK_END);
                long size = ftell(f);
                fseek(f, 0, SEEK_SET);
                char *src = (char *)malloc((size_t)size + 1);
                if (!src) { fclose(f); return NULL; }
                size_t rd = fread(src, 1, (size_t)size, f);
                src[rd] = '\0';
                fclose(f);
                return src;
            }
        }
    }

    for (int i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "r");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *src = (char *)malloc((size_t)size + 1);
        if (!src) { fclose(f); return NULL; }
        size_t rd = fread(src, 1, (size_t)size, f);
        src[rd] = '\0';
        fclose(f);
        return src;
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════
 * OpenCL state
 * ═══════════════════════════════════════════════════════════════════════ */

static cl_platform_id   platform;
static cl_device_id     device;
static cl_context        context;
static cl_command_queue  queue;
static cl_program        program;
static cl_kernel         kernel;
static cl_mem            d_partial_state;
static cl_mem            d_target;
static cl_mem            d_found_nonce;
static cl_mem            d_found_count;
static char              device_name_buf[256];
static cl_ulong          device_mem;
static bool              inited = false;

/* ═══════════════════════════════════════════════════════════════════════
 * Init / shutdown
 * ═══════════════════════════════════════════════════════════════════════ */

bool ocl_init(void) {
    cl_int err;
    cl_uint num_platforms = 0;

    /* Find platform */
    err = clGetPlatformIDs(0, NULL, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        fprintf(stderr, "OpenCL: no platforms found\n");
        return false;
    }

    /* Try all platforms to find a GPU */
    cl_platform_id *platforms = (cl_platform_id *)malloc(num_platforms * sizeof(cl_platform_id));
    clGetPlatformIDs(num_platforms, platforms, NULL);

    bool found_device = false;
    for (cl_uint p = 0; p < num_platforms && !found_device; p++) {
        err = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, 1, &device, NULL);
        if (err == CL_SUCCESS) {
            platform = platforms[p];
            found_device = true;
        }
    }

    /* Fallback to any accelerator or CPU */
    if (!found_device) {
        for (cl_uint p = 0; p < num_platforms && !found_device; p++) {
            err = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL, 1, &device, NULL);
            if (err == CL_SUCCESS) {
                platform = platforms[p];
                found_device = true;
            }
        }
    }
    free(platforms);

    if (!found_device) {
        fprintf(stderr, "OpenCL: no devices found\n");
        return false;
    }

    clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(device_name_buf), device_name_buf, NULL);
    clGetDeviceInfo(device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(device_mem), &device_mem, NULL);

    /* Create context and command queue */
    context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: failed to create context (%d)\n", err);
        return false;
    }

    queue = clCreateCommandQueue(context, device, 0, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: failed to create command queue (%d)\n", err);
        clReleaseContext(context);
        return false;
    }

    /* Load and compile kernel */
    char *kernel_src = load_kernel_source();
    if (!kernel_src) {
        fprintf(stderr, "OpenCL: cannot find ocl_keccak.cl\n");
        clReleaseCommandQueue(queue);
        clReleaseContext(context);
        return false;
    }

    const char *src_ptr = kernel_src;
    program = clCreateProgramWithSource(context, 1, &src_ptr, NULL, &err);
    free(kernel_src);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: failed to create program (%d)\n", err);
        clReleaseCommandQueue(queue);
        clReleaseContext(context);
        return false;
    }

    err = clBuildProgram(program, 1, &device, "-cl-std=CL1.2", NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t log_size = 0;
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
        char *log = (char *)malloc(log_size + 1);
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
        log[log_size] = '\0';
        fprintf(stderr, "OpenCL build error:\n%s\n", log);
        free(log);
        clReleaseProgram(program);
        clReleaseCommandQueue(queue);
        clReleaseContext(context);
        return false;
    }

    kernel = clCreateKernel(program, "mine_keccak256d", &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "OpenCL: failed to create kernel (%d)\n", err);
        clReleaseProgram(program);
        clReleaseCommandQueue(queue);
        clReleaseContext(context);
        return false;
    }

    /* Allocate GPU buffers */
    d_partial_state = clCreateBuffer(context, CL_MEM_READ_ONLY, 92, NULL, &err);  /* raw header */
    d_target        = clCreateBuffer(context, CL_MEM_READ_ONLY, 32, NULL, &err);
    d_found_nonce   = clCreateBuffer(context, CL_MEM_READ_WRITE, sizeof(cl_uint), NULL, &err);
    d_found_count   = clCreateBuffer(context, CL_MEM_READ_WRITE, sizeof(cl_uint), NULL, &err);

    inited = true;
    return true;
}

void ocl_shutdown(void) {
    if (!inited) return;
    clReleaseMemObject(d_partial_state);
    clReleaseMemObject(d_target);
    clReleaseMemObject(d_found_nonce);
    clReleaseMemObject(d_found_count);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(context);
    inited = false;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Pre-compute partial Keccak state from header
 * ═══════════════════════════════════════════════════════════════════════ */

static void precompute_partial_state(const uint8_t *header, int header_len,
                                     uint64_t *partial_state) {
    /* Zero state */
    memset(partial_state, 0, 25 * sizeof(uint64_t));

    /*
     * Absorb header into state with Keccak padding.
     * Rate = 136 bytes (1088 bits for Keccak-256).
     * header_len < 136, so it fits in one block.
     */
    uint8_t padded[136];
    memset(padded, 0, 136);
    memcpy(padded, header, (size_t)header_len);
    /* Zero out nonce field — kernel will XOR its own nonce */
    memset(padded + 84, 0, 4);
    padded[header_len] = 0x01;      /* Keccak padding start */
    padded[135] |= 0x80;            /* End of rate */

    /* XOR padded block into state (17 uint64 words = 136 bytes) */
    for (int i = 0; i < 17; i++) {
        uint64_t word;
        memcpy(&word, padded + i * 8, 8);
        partial_state[i] = word;
    }
    /*
     * NOTE: Do NOT run the permutation here.
     * The kernel will XOR the nonce into the correct word and
     * then run both permutations (for the double hash).
     */
}

/* ═══════════════════════════════════════════════════════════════════════
 * Mine a batch of nonces
 * ═══════════════════════════════════════════════════════════════════════ */

bool ocl_mine_batch(const uint8_t *header, int header_len,
                    const uint8_t *target,
                    int nonce_offset,
                    uint32_t start_nonce, uint32_t batch_size,
                    uint32_t *found_nonce) {
    if (!inited) return false;

    (void)header_len;  /* always 92 */

    /* Zero nonce in header before uploading */
    uint8_t header_copy[92];
    memcpy(header_copy, header, 92);
    memset(header_copy + nonce_offset, 0, 4);

    /* Upload raw header and target to GPU */
    clEnqueueWriteBuffer(queue, d_partial_state, CL_TRUE, 0,
                         92, header_copy, 0, NULL, NULL);
    clEnqueueWriteBuffer(queue, d_target, CL_TRUE, 0,
                         32, target, 0, NULL, NULL);

    cl_uint zero = 0;
    clEnqueueWriteBuffer(queue, d_found_nonce, CL_TRUE, 0, sizeof(cl_uint),
                         &zero, 0, NULL, NULL);
    clEnqueueWriteBuffer(queue, d_found_count, CL_TRUE, 0, sizeof(cl_uint),
                         &zero, 0, NULL, NULL);

    /* Set kernel arguments — new kernel signature:
     * (header, target, start_nonce, nonce_offset, found_nonce, found_count) */
    cl_uint cl_nonce_offset = (cl_uint)nonce_offset;
    clSetKernelArg(kernel, 0, sizeof(cl_mem), &d_partial_state);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &d_target);
    clSetKernelArg(kernel, 2, sizeof(cl_uint), &start_nonce);
    clSetKernelArg(kernel, 3, sizeof(cl_uint), &cl_nonce_offset);
    clSetKernelArg(kernel, 4, sizeof(cl_mem), &d_found_nonce);
    clSetKernelArg(kernel, 5, sizeof(cl_mem), &d_found_count);

    /* Launch kernel */
    size_t global_size = (size_t)batch_size;
    size_t local_size  = 256;

    /* Round global_size up to multiple of local_size */
    if (global_size % local_size != 0)
        global_size += local_size - (global_size % local_size);

    clEnqueueNDRangeKernel(queue, kernel, 1, NULL,
                           &global_size, &local_size, 0, NULL, NULL);
    clFinish(queue);

    /* Read results */
    cl_uint count = 0;
    clEnqueueReadBuffer(queue, d_found_count, CL_TRUE, 0, sizeof(cl_uint),
                        &count, 0, NULL, NULL);

    if (count > 0) {
        clEnqueueReadBuffer(queue, d_found_nonce, CL_TRUE, 0, sizeof(cl_uint),
                            found_nonce, 0, NULL, NULL);
        return true;
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Info accessors
 * ═══════════════════════════════════════════════════════════════════════ */

const char *ocl_device_name(void) { return device_name_buf; }
uint64_t ocl_total_memory(void) { return (uint64_t)device_mem; }
