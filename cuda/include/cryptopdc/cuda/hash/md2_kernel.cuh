#pragma once

#include <cuda_runtime.h>
#include <cstdint>

namespace cryptopdc {
namespace cuda {
namespace hash {

__global__ void md2_crack_kernel(
    const uint8_t* target_hash,
    const uint64_t start_index,
    const uint64_t count,
    const char* charset,
    const int charset_len,
    const int key_length,
    char* result_key,
    int* found_flag
);

cudaError_t launch_md2_crack(
    const uint8_t* target_hash,
    uint64_t start_index,
    uint64_t count,
    const char* charset,
    int charset_len,
    int key_length,
    char* result_key,
    int* found_flag,
    int device_id = 0
);

} // namespace hash
} // namespace cuda
} // namespace cryptopdc
