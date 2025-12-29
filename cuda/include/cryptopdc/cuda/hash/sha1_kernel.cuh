#pragma once

#include <cuda_runtime.h>
#include <cstdint>

namespace cryptopdc {
namespace cuda {
namespace hash {

// SHA-1 CUDA kernel for brute force attack
__global__ void sha1_crack_kernel(
    const uint8_t* target_hash,      // Target SHA-1 hash (20 bytes)
    const uint64_t start_index,      // Starting keyspace index
    const uint64_t count,            // Number of keys to test
    const char* charset,             // Character set
    const int charset_len,           // Length of charset
    const int key_length,            // Length of keys to test
    char* result_key,                // Output: found key
    int* found_flag                  // Atomic flag: 1 if found
);

// Host function to launch SHA-1 cracking
cudaError_t launch_sha1_crack(
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
