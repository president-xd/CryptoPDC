#include "cryptopdc/cuda/hash/sha256_kernel.cuh"
#include "cryptopdc/cuda/common.cuh"
#include <cstring>

namespace cryptopdc {
namespace cuda {
namespace hash {

// SHA-256 constants (device)
__constant__ uint32_t d_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ __forceinline__ uint32_t right_rotate(uint32_t val, uint32_t n) {
    return (val >> n) | (val << (32 - n));
}

__device__ __forceinline__ uint32_t choice(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__device__ __forceinline__ uint32_t major(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ uint32_t sigma0(uint32_t x) {
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22);
}

__device__ __forceinline__ uint32_t sigma1(uint32_t x) {
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25);
}

__device__ __forceinline__ uint32_t delta0(uint32_t x) {
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3);
}

__device__ __forceinline__ uint32_t delta1(uint32_t x) {
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10);
}

// Device SHA-256 computation
__device__ void sha256_hash_device(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // Message buffer (max 128 bytes for typical password cracking)
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
    
    // Append length (big-endian)
    uint64_t bits_len = length * 8;
    for (int i = 0; i < 8; i++) {
        msg[new_len + i] = (bits_len >> (56 - i * 8)) & 0xFF;
    }
    
    // Process 512-bit chunks
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t w[64];
        
        // Prepare message schedule
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[offset + i * 4] << 24) |
                   (msg[offset + i * 4 + 1] << 16) |
                   (msg[offset + i * 4 + 2] << 8) |
                   (msg[offset + i * 4 + 3]);
        }
        
        for (int i = 16; i < 64; i++) {
            w[i] = delta1(w[i - 2]) + w[i - 7] + delta0(w[i - 15]) + w[i - 16];
        }
        
        // Working variables
        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t hh = h[7];
        
        // Compression loop
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + sigma1(e) + choice(e, f, g) + d_sha256_k[i] + w[i];
            uint32_t t2 = sigma0(a) + major(a, b, c);
            
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        // Add to hash state
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
    
    // Output (big-endian)
    for (int i = 0; i < 8; i++) {
        output[i * 4] = (h[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        output[i * 4 + 3] = h[i] & 0xFF;
    }
}

__global__ void sha256_crack_kernel(
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
    
    // Early exit
    if (*found_flag) return;
    
    // Generate candidate key
    char candidate[64];
    index_to_key_device(start_index + idx, candidate, charset, charset_len, key_length);
    
    // Compute SHA-256 hash
    uint8_t hash[32];
    sha256_hash_device(reinterpret_cast<const uint8_t*>(candidate), key_length, hash);
    
    // Compare
    if (memcmp_device(hash, target_hash, 32)) {
        // Found!
        int old = atomicExch(found_flag, 1);
        if (old == 0) {
            for (int i = 0; i <= key_length; i++) {
                result_key[i] = candidate[i];
            }
        }
    }
}

cudaError_t launch_sha256_crack(
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
    
    CUDA_CHECK(cudaMalloc(&d_target_hash, 32));
    CUDA_CHECK(cudaMalloc(&d_charset, charset_len));
    CUDA_CHECK(cudaMalloc(&d_result_key, 64));
    CUDA_CHECK(cudaMalloc(&d_found_flag, sizeof(int)));
    
    // Copy data to device
    CUDA_CHECK(cudaMemcpy(d_target_hash, target_hash, 32, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_charset, charset, charset_len, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemset(d_found_flag, 0, sizeof(int)));
    
    // Launch configuration
    int threads_per_block = 256;
    uint64_t total_blocks = (count + threads_per_block - 1) / threads_per_block;
    
    // Limit blocks to CUDA's maximum grid dimension
    int max_blocks = 65535;
    int blocks = (total_blocks > max_blocks) ? max_blocks : static_cast<int>(total_blocks);
    
    // Launch kernel
    sha256_crack_kernel<<<blocks, threads_per_block>>>(
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
