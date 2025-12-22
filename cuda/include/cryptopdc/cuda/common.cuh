#pragma once

#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>

namespace cryptopdc {
namespace cuda {

// CUDA error checking macro
#define CUDA_CHECK(call) \
    do { \
        cudaError_t err = call; \
        if (err != cudaSuccess) { \
            fprintf(stderr, "CUDA error at %s:%d: %s\n", __FILE__, __LINE__, \
                    cudaGetErrorString(err)); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

// Device helper functions
__device__ __forceinline__ uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

__device__ __forceinline__ uint32_t rotl(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// Index to key conversion (device function)
__device__ inline void index_to_key_device(uint64_t index, char* output, 
                                     const char* charset, int charset_len, 
                                     int key_length) {
    for (int i = key_length - 1; i >= 0; --i) {
        output[i] = charset[index % charset_len];
        index /= charset_len;
    }
    output[key_length] = '\0';
}

// Memory comparison (device function)
__device__ inline bool memcmp_device(const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

} // namespace cuda
} // namespace cryptopdc
