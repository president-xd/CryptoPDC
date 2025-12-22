#include "cryptopdc/cuda/hash/md5_kernel.cuh"
#include "cryptopdc/cuda/common.cuh"
#include <cstring>

namespace cryptopdc {
namespace cuda {
namespace hash {

// MD5 constants (device)
__constant__ uint32_t d_md5_s[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

__constant__ uint32_t d_md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// Device MD5 computation
__device__ void md5_hash_device(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;
    
    // For small inputs (typical passwords), we can use stack allocation
    uint8_t msg[128];
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    
    // Copy input
    for (size_t i = 0; i < length; i++) {
        msg[i] = input[i];
    }
    msg[length] = 0x80;
    
    // Padding
    for (size_t i = length + 1; i < new_len; i++) {
        msg[i] = 0;
    }
    
    // Append length
    uint64_t bits_len = length * 8;
    memcpy(msg + new_len, &bits_len, 8);
    
    // Process 512-bit chunks
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t* w = (uint32_t*)(msg + offset);
        
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t f, g;
            
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
            
            uint32_t temp = d;
            d = c;
            c = b;
            b = b + rotl((a + f + d_md5_k[i] + w[g]), d_md5_s[i]);
            a = temp;
        }
        
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }
    
    // Output (little-endian)
    memcpy(output, &h0, 4);
    memcpy(output + 4, &h1, 4);
    memcpy(output + 8, &h2, 4);
    memcpy(output + 12, &h3, 4);
}

__global__ void md5_crack_kernel(
    const uint8_t* target_hash,
    const uint64_t start_index,
    const uint64_t count,
    const char* charset,
    const int charset_len,
    const int key_length,
    char* result_key,
    int* found_flag
) {
    uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (idx >= count) return;
    
    // Early exit if solution already found
    if (*found_flag) return;
    
    // Generate candidate key from index
    char candidate[64];
    index_to_key_device(start_index + idx, candidate, charset, charset_len, key_length);
    
    // Compute MD5 hash
    uint8_t hash[16];
    md5_hash_device(reinterpret_cast<const uint8_t*>(candidate), key_length, hash);
    
    // Compare with target
    if (memcmp_device(hash, target_hash, 16)) {
        // Found! Use atomic operation to ensure only one thread writes
        int old = atomicExch(found_flag, 1);
        if (old == 0) {
            // First thread to find it, copy the result
            for (int i = 0; i <= key_length; i++) {
                result_key[i] = candidate[i];
            }
        }
    }
}

cudaError_t launch_md5_crack(
    const uint8_t* target_hash,
    uint64_t start_index,
    uint64_t count,
    const char* charset,
    int charset_len,
    int key_length,
    char* result_key,
    int* found_flag,
    int device_id
) {
    // Set device
    CUDA_CHECK(cudaSetDevice(device_id));
    
    // Allocate device memory
    uint8_t* d_target_hash;
    char* d_charset;
    char* d_result_key;
    int* d_found_flag;
    
    CUDA_CHECK(cudaMalloc(&d_target_hash, 16));
    CUDA_CHECK(cudaMalloc(&d_charset, charset_len));
    CUDA_CHECK(cudaMalloc(&d_result_key, 64));
    CUDA_CHECK(cudaMalloc(&d_found_flag, sizeof(int)));
    
    // Copy data to device
    CUDA_CHECK(cudaMemcpy(d_target_hash, target_hash, 16, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_charset, charset, charset_len, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemset(d_found_flag, 0, sizeof(int)));
    
    // Launch configuration
    int threads_per_block = 256;
    int blocks = (count + threads_per_block - 1) / threads_per_block;
    
    // Launch kernel
    md5_crack_kernel<<<blocks, threads_per_block>>>(
        d_target_hash, start_index, count, d_charset, charset_len,
        key_length, d_result_key, d_found_flag
    );
    
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());
    
    // Copy results back
    CUDA_CHECK(cudaMemcpy(found_flag, d_found_flag, sizeof(int), cudaMemcpyDeviceToHost));
    if (*found_flag) {
        CUDA_CHECK(cudaMemcpy(result_key, d_result_key, 64, cudaMemcpyDeviceToHost));
    }
    
    // Cleanup
    CUDA_CHECK(cudaFree(d_target_hash));
    CUDA_CHECK(cudaFree(d_charset));
    CUDA_CHECK(cudaFree(d_result_key));
    CUDA_CHECK(cudaFree(d_found_flag));
    
    return cudaSuccess;
}

} // namespace hash
} // namespace cuda
} // namespace cryptopdc
