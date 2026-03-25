#include "backend.h"
#include "backend_cpu.h"

#ifdef FLOWCOIN_USE_CUDA
#include "backend_cuda.h"
#endif

#ifdef FLOWCOIN_USE_VULKAN
#include "backend_vulkan.h"
#endif

#ifdef FLOWCOIN_USE_METAL
#include "backend_metal.h"
#endif

#ifdef FLOWCOIN_USE_OPENCL
#include "backend_opencl.h"
#endif

namespace flow::miner {

std::string backend_name(BackendType type) {
    switch (type) {
        case BackendType::CPU:    return "CPU";
        case BackendType::CUDA:   return "CUDA";
        case BackendType::METAL:  return "Metal";
        case BackendType::VULKAN: return "Vulkan";
        case BackendType::OPENCL: return "OpenCL";
    }
    return "Unknown";
}

std::vector<BackendType> available_backends() {
    std::vector<BackendType> result;
    result.push_back(BackendType::CPU); // always available

#ifdef FLOWCOIN_USE_CUDA
    result.push_back(BackendType::CUDA);
#endif
#ifdef FLOWCOIN_USE_VULKAN
    result.push_back(BackendType::VULKAN);
#endif
#ifdef FLOWCOIN_USE_METAL
    result.push_back(BackendType::METAL);
#endif
#ifdef FLOWCOIN_USE_OPENCL
    result.push_back(BackendType::OPENCL);
#endif

    return result;
}

std::unique_ptr<ComputeBackend> create_backend(BackendType type) {
    switch (type) {
        case BackendType::CPU: {
            auto b = std::make_unique<CPUBackend>();
            b->init();
            return b;
        }
#ifdef FLOWCOIN_USE_CUDA
        case BackendType::CUDA: {
            auto b = std::make_unique<CUDABackend>();
            if (b->init()) return b;
            return nullptr;
        }
#endif
#ifdef FLOWCOIN_USE_VULKAN
        case BackendType::VULKAN: {
            auto b = std::make_unique<VulkanBackend>();
            if (b->init()) return b;
            return nullptr;
        }
#endif
#ifdef FLOWCOIN_USE_METAL
        case BackendType::METAL: {
            auto b = std::make_unique<MetalBackend>();
            if (b->init()) return b;
            return nullptr;
        }
#endif
#ifdef FLOWCOIN_USE_OPENCL
        case BackendType::OPENCL: {
            auto b = std::make_unique<OpenCLBackend>();
            if (b->init()) return b;
            return nullptr;
        }
#endif
        default:
            return nullptr;
    }
}

std::unique_ptr<ComputeBackend> create_best_backend() {
    // Priority: CUDA > Metal > Vulkan > OpenCL > CPU

#ifdef FLOWCOIN_USE_CUDA
    {
        auto b = std::make_unique<CUDABackend>();
        if (b->init()) return b;
    }
#endif

#ifdef FLOWCOIN_USE_METAL
    {
        auto b = std::make_unique<MetalBackend>();
        if (b->init()) return b;
    }
#endif

#ifdef FLOWCOIN_USE_VULKAN
    {
        auto b = std::make_unique<VulkanBackend>();
        if (b->init()) return b;
    }
#endif

#ifdef FLOWCOIN_USE_OPENCL
    {
        auto b = std::make_unique<OpenCLBackend>();
        if (b->init()) return b;
    }
#endif

    // CPU is always available
    auto cpu = std::make_unique<CPUBackend>();
    cpu->init();
    return cpu;
}

} // namespace flow::miner
