#ifdef FLOWCOIN_USE_VULKAN
#include "backend_vulkan.h"
#include "backend_cpu.h"
#include <cstring>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <cstdlib>

namespace flow::miner {

// ----------------------------------------------------------------
// Init / Shutdown
// ----------------------------------------------------------------

bool VulkanBackend::init() {
    if (initialized_) return true;

    // Create Vulkan instance
    VkApplicationInfo app_info = {};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "FlowCoin Miner";
    app_info.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.pEngineName = "FlowCoin";
    app_info.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.apiVersion = VK_API_VERSION_1_0;

    VkInstanceCreateInfo create_info = {};
    create_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    create_info.pApplicationInfo = &app_info;

    if (vkCreateInstance(&create_info, nullptr, &instance_) != VK_SUCCESS) {
        fprintf(stderr, "Vulkan: failed to create instance\n");
        return false;
    }

    // Pick physical device
    uint32_t device_count = 0;
    vkEnumeratePhysicalDevices(instance_, &device_count, nullptr);
    if (device_count == 0) {
        fprintf(stderr, "Vulkan: no devices found\n");
        vkDestroyInstance(instance_, nullptr);
        instance_ = VK_NULL_HANDLE;
        return false;
    }

    std::vector<VkPhysicalDevice> devices(device_count);
    vkEnumeratePhysicalDevices(instance_, &device_count, devices.data());

    // Prefer discrete GPU
    physical_device_ = devices[0];
    for (auto& dev : devices) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(dev, &props);
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            physical_device_ = dev;
            break;
        }
    }

    vkGetPhysicalDeviceProperties(physical_device_, &device_props_);
    vkGetPhysicalDeviceMemoryProperties(physical_device_, &mem_props_);

    // Find compute queue family
    uint32_t queue_family_count = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device_,
                                             &queue_family_count, nullptr);
    std::vector<VkQueueFamilyProperties> queue_families(queue_family_count);
    vkGetPhysicalDeviceQueueFamilyProperties(physical_device_,
                                             &queue_family_count,
                                             queue_families.data());

    bool found_compute = false;
    for (uint32_t i = 0; i < queue_family_count; ++i) {
        if (queue_families[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            compute_family_ = i;
            found_compute = true;
            break;
        }
    }
    if (!found_compute) {
        fprintf(stderr, "Vulkan: no compute queue family\n");
        vkDestroyInstance(instance_, nullptr);
        instance_ = VK_NULL_HANDLE;
        return false;
    }

    // Create logical device
    float queue_priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info = {};
    queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_info.queueFamilyIndex = compute_family_;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &queue_priority;

    VkDeviceCreateInfo device_info = {};
    device_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    device_info.queueCreateInfoCount = 1;
    device_info.pQueueCreateInfos = &queue_info;

    if (vkCreateDevice(physical_device_, &device_info, nullptr, &device_) != VK_SUCCESS) {
        fprintf(stderr, "Vulkan: failed to create logical device\n");
        vkDestroyInstance(instance_, nullptr);
        instance_ = VK_NULL_HANDLE;
        return false;
    }

    vkGetDeviceQueue(device_, compute_family_, 0, &compute_queue_);

    // Create command pool
    VkCommandPoolCreateInfo pool_info = {};
    pool_info.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_info.queueFamilyIndex = compute_family_;
    pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

    if (vkCreateCommandPool(device_, &pool_info, nullptr, &command_pool_) != VK_SUCCESS) {
        fprintf(stderr, "Vulkan: failed to create command pool\n");
        vkDestroyDevice(device_, nullptr);
        vkDestroyInstance(instance_, nullptr);
        device_ = VK_NULL_HANDLE;
        instance_ = VK_NULL_HANDLE;
        return false;
    }

    // Create CPU fallback for ops not yet implemented on GPU
    cpu_fallback_ = new CPUBackend();
    cpu_fallback_->init();

    initialized_ = true;
    return true;
}

void VulkanBackend::shutdown() {
    if (!initialized_) return;

    delete cpu_fallback_;
    cpu_fallback_ = nullptr;

    if (command_pool_ != VK_NULL_HANDLE)
        vkDestroyCommandPool(device_, command_pool_, nullptr);
    if (device_ != VK_NULL_HANDLE)
        vkDestroyDevice(device_, nullptr);
    if (instance_ != VK_NULL_HANDLE)
        vkDestroyInstance(instance_, nullptr);

    command_pool_ = VK_NULL_HANDLE;
    device_ = VK_NULL_HANDLE;
    instance_ = VK_NULL_HANDLE;
    initialized_ = false;
}

// ----------------------------------------------------------------
// Device info
// ----------------------------------------------------------------

std::string VulkanBackend::device_name() const {
    return std::string(device_props_.deviceName);
}

size_t VulkanBackend::total_memory() const {
    size_t total = 0;
    for (uint32_t i = 0; i < mem_props_.memoryHeapCount; ++i) {
        if (mem_props_.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
            total += mem_props_.memoryHeaps[i].size;
        }
    }
    return total;
}

size_t VulkanBackend::available_memory() const {
    // Vulkan 1.0 has no direct query for free memory;
    // return total as an approximation
    return total_memory();
}

// ----------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------

uint32_t VulkanBackend::find_memory_type(uint32_t type_filter,
                                         VkMemoryPropertyFlags props) const {
    for (uint32_t i = 0; i < mem_props_.memoryTypeCount; ++i) {
        if ((type_filter & (1 << i)) &&
            (mem_props_.memoryTypes[i].propertyFlags & props) == props) {
            return i;
        }
    }
    return 0;
}

VkCommandBuffer VulkanBackend::begin_single_command() const {
    VkCommandBufferAllocateInfo alloc_info = {};
    alloc_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc_info.commandPool = command_pool_;
    alloc_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc_info.commandBufferCount = 1;

    VkCommandBuffer cmd;
    vkAllocateCommandBuffers(device_, &alloc_info, &cmd);

    VkCommandBufferBeginInfo begin_info = {};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cmd, &begin_info);

    return cmd;
}

void VulkanBackend::end_single_command(VkCommandBuffer cmd) const {
    vkEndCommandBuffer(cmd);

    VkSubmitInfo submit_info = {};
    submit_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount = 1;
    submit_info.pCommandBuffers = &cmd;

    vkQueueSubmit(compute_queue_, 1, &submit_info, VK_NULL_HANDLE);
    vkQueueWaitIdle(compute_queue_);

    vkFreeCommandBuffers(device_, command_pool_, 1, &cmd);
}

// ----------------------------------------------------------------
// Memory management
//
// For simplicity, we use host-visible + host-coherent memory so
// that upload/download are simple memcpy operations through
// mapped pointers. A production backend would use staging buffers
// and device-local memory for compute operations.
// ----------------------------------------------------------------

struct VulkanAlloc {
    VkBuffer buffer;
    VkDeviceMemory memory;
    void* mapped;
    size_t size;
    VkDevice device;
};

void* VulkanBackend::alloc(size_t bytes) {
    VkBufferCreateInfo buf_info = {};
    buf_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buf_info.size = bytes;
    buf_info.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                     VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                     VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    buf_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkBuffer buffer;
    if (vkCreateBuffer(device_, &buf_info, nullptr, &buffer) != VK_SUCCESS) {
        fprintf(stderr, "Vulkan: failed to create buffer\n");
        return nullptr;
    }

    VkMemoryRequirements mem_req;
    vkGetBufferMemoryRequirements(device_, buffer, &mem_req);

    VkMemoryAllocateInfo mem_alloc = {};
    mem_alloc.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    mem_alloc.allocationSize = mem_req.size;
    mem_alloc.memoryTypeIndex = find_memory_type(
        mem_req.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
        VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);

    VkDeviceMemory memory;
    if (vkAllocateMemory(device_, &mem_alloc, nullptr, &memory) != VK_SUCCESS) {
        vkDestroyBuffer(device_, buffer, nullptr);
        fprintf(stderr, "Vulkan: failed to allocate memory\n");
        return nullptr;
    }

    vkBindBufferMemory(device_, buffer, memory, 0);

    void* mapped = nullptr;
    vkMapMemory(device_, memory, 0, bytes, 0, &mapped);

    auto* handle = new VulkanAlloc{buffer, memory, mapped, bytes, device_};
    return static_cast<void*>(handle);
}

void VulkanBackend::free(void* ptr) {
    if (!ptr) return;
    auto* handle = static_cast<VulkanAlloc*>(ptr);
    vkUnmapMemory(handle->device, handle->memory);
    vkDestroyBuffer(handle->device, handle->buffer, nullptr);
    vkFreeMemory(handle->device, handle->memory, nullptr);
    delete handle;
}

void VulkanBackend::upload(void* dst, const float* src, size_t count) {
    auto* handle = static_cast<VulkanAlloc*>(dst);
    std::memcpy(handle->mapped, src, count * sizeof(float));
}

void VulkanBackend::download(float* dst, const void* src, size_t count) {
    auto* handle = static_cast<const VulkanAlloc*>(src);
    std::memcpy(dst, handle->mapped, count * sizeof(float));
}

// ----------------------------------------------------------------
// Compute operations
//
// matmul: CPU fallback (compute shader pipeline would be added
// for production; requires SPIR-V binary embedding)
//
// All other ops: CPU fallback through mapped memory
// ----------------------------------------------------------------

// Helper: get the float pointer from a VulkanAlloc handle
static const float* vk_fptr(const void* handle) {
    return static_cast<const float*>(static_cast<const VulkanAlloc*>(handle)->mapped);
}

static float* vk_fptr_mut(void* handle) {
    return static_cast<float*>(static_cast<VulkanAlloc*>(handle)->mapped);
}

void VulkanBackend::matmul(const void* A, const void* B, void* C,
                           int M, int N, int K) {
    // CPU fallback via mapped memory
    cpu_fallback_->matmul(vk_fptr(A), vk_fptr(B), vk_fptr_mut(C), M, N, K);
}

void VulkanBackend::rms_norm(const void* x, const void* w, void* out,
                             int rows, int cols) {
    cpu_fallback_->rms_norm(vk_fptr(x), vk_fptr(w), vk_fptr_mut(out), rows, cols);
}

void VulkanBackend::silu(const void* x, void* out, int n) {
    cpu_fallback_->silu(vk_fptr(x), vk_fptr_mut(out), n);
}

void VulkanBackend::sigmoid(const void* x, void* out, int n) {
    cpu_fallback_->sigmoid(vk_fptr(x), vk_fptr_mut(out), n);
}

void VulkanBackend::mul(const void* a, const void* b, void* out, int n) {
    cpu_fallback_->mul(vk_fptr(a), vk_fptr(b), vk_fptr_mut(out), n);
}

void VulkanBackend::add(const void* a, const void* b, void* out, int n) {
    cpu_fallback_->add(vk_fptr(a), vk_fptr(b), vk_fptr_mut(out), n);
}

void VulkanBackend::softmax(const void* x, void* out, int rows, int cols) {
    cpu_fallback_->softmax(vk_fptr(x), vk_fptr_mut(out), rows, cols);
}

float VulkanBackend::cross_entropy(const void* logits, const uint8_t* targets,
                                   int seq_len, int vocab) {
    return cpu_fallback_->cross_entropy(vk_fptr(logits), targets, seq_len, vocab);
}

void VulkanBackend::topk(const void* scores, int* indices, float* values,
                         int n, int k) {
    cpu_fallback_->topk(vk_fptr(scores), indices, values, n, k);
}

void VulkanBackend::sgd_update(void* weights, const void* grads, float lr, int n) {
    cpu_fallback_->sgd_update(vk_fptr_mut(weights), vk_fptr(grads), lr, n);
}

void VulkanBackend::sync() {
    if (device_ != VK_NULL_HANDLE)
        vkDeviceWaitIdle(device_);
}

} // namespace flow::miner

#endif // FLOWCOIN_USE_VULKAN
