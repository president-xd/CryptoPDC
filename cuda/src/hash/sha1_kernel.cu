#include "cryptopdc/cuda/hash/sha1_kernel.cuh"
#include "cryptopdc/cuda/common.cuh"
#include <cstring>

namespace cryptopdc {
namespace cuda {
namespace hash {

// SHA-1 constants (device constant memory for fast access)
__constant__ uint32_t d_sha1_k[4] = {
    0x5A827999,  // Rounds 0-19
    0x6ED9EBA1,  // Rounds 20-39
    0x8F1BBCDC,  // Rounds 40-59
    0xCA62C1D6   // Rounds 60-79
};

// SHA-1 initial hash values
__constant__ uint32_t d_sha1_h0[5] = {
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0
};

// Device SHA-1 computation - fully implemented on GPU
__device__ void sha1_hash_device(const uint8_t* input, size_t length, uint8_t* output) {
    // Initialize hash values
    uint32_t h0 = d_sha1_h0[0];
    uint32_t h1 = d_sha1_h0[1];
    uint32_t h2 = d_sha1_h0[2];
    uint32_t h3 = d_sha1_h0[3];
    uint32_t h4 = d_sha1_h0[4];
    
    // Message buffer (max 128 bytes for typical password cracking)
    // This handles messages up to 55 bytes in a single block, or up to ~119 bytes in two blocks
    uint8_t msg[128];
    
    // Calculate padded message length (must be multiple of 64 bytes / 512 bits)
    // new_len = length of message + padding + 8 bytes for length, rounded to 64
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    
    // Copy input to message buffer
    for (size_t i = 0; i < length && i < 119; i++) {
        msg[i] = input[i];
    }
    
    // Append '1' bit (0x80)
    msg[length] = 0x80;
    
    // Padding with zeros
    for (size_t i = length + 1; i < new_len; i++) {
        msg[i] = 0;
    }
    
    // Append original message length in bits as 64-bit big-endian
    uint64_t bits_len = length * 8;
    msg[new_len + 0] = (bits_len >> 56) & 0xFF;
    msg[new_len + 1] = (bits_len >> 48) & 0xFF;
    msg[new_len + 2] = (bits_len >> 40) & 0xFF;
    msg[new_len + 3] = (bits_len >> 32) & 0xFF;
    msg[new_len + 4] = (bits_len >> 24) & 0xFF;
    msg[new_len + 5] = (bits_len >> 16) & 0xFF;
    msg[new_len + 6] = (bits_len >> 8) & 0xFF;
    msg[new_len + 7] = bits_len & 0xFF;
    
    // Process message in 512-bit (64-byte) chunks
    for (size_t offset = 0; offset < new_len + 8; offset += 64) {
        // Message schedule array
        uint32_t w[80];
        
        // Break chunk into sixteen 32-bit big-endian words
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)msg[offset + i * 4] << 24) |
                   ((uint32_t)msg[offset + i * 4 + 1] << 16) |
                   ((uint32_t)msg[offset + i * 4 + 2] << 8) |
                   ((uint32_t)msg[offset + i * 4 + 3]);
        }
        
        // Extend the sixteen 32-bit words into eighty 32-bit words
        for (int i = 16; i < 80; i++) {
            uint32_t temp = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
            w[i] = rotl(temp, 1);  // Left rotate by 1
        }
        
        // Initialize working variables
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        
        // Main loop - 80 rounds
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            
            if (i < 20) {
                // Ch(b, c, d) = (b AND c) XOR ((NOT b) AND d)
                f = (b & c) | ((~b) & d);
                k = d_sha1_k[0];
            } else if (i < 40) {
                // Parity(b, c, d) = b XOR c XOR d
                f = b ^ c ^ d;
                k = d_sha1_k[1];
            } else if (i < 60) {
                // Maj(b, c, d) = (b AND c) XOR (b AND d) XOR (c AND d)
                f = (b & c) | (b & d) | (c & d);
                k = d_sha1_k[2];
            } else {
                // Parity(b, c, d) = b XOR c XOR d
                f = b ^ c ^ d;
                k = d_sha1_k[3];
            }
            
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }
        
        // Add this chunk's hash to result so far
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    
    // Produce the final hash value (big-endian) - 160 bits = 20 bytes
    output[0] = (h0 >> 24) & 0xFF;
    output[1] = (h0 >> 16) & 0xFF;
    output[2] = (h0 >> 8) & 0xFF;
    output[3] = h0 & 0xFF;
    
    output[4] = (h1 >> 24) & 0xFF;
    output[5] = (h1 >> 16) & 0xFF;
    output[6] = (h1 >> 8) & 0xFF;
    output[7] = h1 & 0xFF;
    
    output[8] = (h2 >> 24) & 0xFF;
    output[9] = (h2 >> 16) & 0xFF;
    output[10] = (h2 >> 8) & 0xFF;
    output[11] = h2 & 0xFF;
    
    output[12] = (h3 >> 24) & 0xFF;
    output[13] = (h3 >> 16) & 0xFF;
    output[14] = (h3 >> 8) & 0xFF;
    output[15] = h3 & 0xFF;
    
    output[16] = (h4 >> 24) & 0xFF;
    output[17] = (h4 >> 16) & 0xFF;
    output[18] = (h4 >> 8) & 0xFF;
    output[19] = h4 & 0xFF;
}

__global__ void sha1_crack_kernel(
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
    
    // Early exit if solution already found by another thread
    if (*found_flag) return;
    
    // Generate candidate key from index
    char candidate[64];
    index_to_key_device(start_index + idx, candidate, charset, charset_len, key_length);
    
    // Compute SHA-1 hash on GPU
    uint8_t hash[20];
    sha1_hash_device(reinterpret_cast<const uint8_t*>(candidate), key_length, hash);
    
    // Compare with target hash (20 bytes for SHA-1)
    if (memcmp_device(hash, target_hash, 20)) {
        // Found! Use atomic operation to ensure only one thread writes result
        int old = atomicExch(found_flag, 1);
        if (old == 0) {
            // First thread to find it, copy the result
            for (int i = 0; i <= key_length; i++) {
                result_key[i] = candidate[i];
            }
        }
    }
}

cudaError_t launch_sha1_crack(
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
    
    CUDA_CHECK(cudaMalloc(&d_target_hash, 20));  // SHA-1 = 20 bytes
    CUDA_CHECK(cudaMalloc(&d_charset, charset_len));
    CUDA_CHECK(cudaMalloc(&d_result_key, 64));
    CUDA_CHECK(cudaMalloc(&d_found_flag, sizeof(int)));
    
    // Copy data to device
    CUDA_CHECK(cudaMemcpy(d_target_hash, target_hash, 20, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_charset, charset, charset_len, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemset(d_found_flag, 0, sizeof(int)));
    
    // Launch configuration
    int threads_per_block = 256;
    int max_blocks = 65535;
    uint64_t chunk_size = static_cast<uint64_t>(max_blocks) * threads_per_block;
    
    // Initialize found flag
    *found_flag = 0;
    
    // Process keyspace in chunks to handle huge keyspaces
    uint64_t processed = 0;
    while (processed < count && !(*found_flag)) {
        uint64_t remaining = count - processed;
        uint64_t current_chunk = (remaining > chunk_size) ? chunk_size : remaining;
        uint64_t current_start = start_index + processed;
        
        uint64_t total_blocks = (current_chunk + threads_per_block - 1) / threads_per_block;
        int blocks = (total_blocks > max_blocks) ? max_blocks : static_cast<int>(total_blocks);
        
        // Launch kernel for this chunk
        sha1_crack_kernel<<<blocks, threads_per_block>>>(
            d_target_hash, current_start, current_chunk, d_charset, charset_len,
            key_length, d_result_key, d_found_flag
        );
        
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaDeviceSynchronize());
        
        // Check if found
        CUDA_CHECK(cudaMemcpy(found_flag, d_found_flag, sizeof(int), cudaMemcpyDeviceToHost));
        
        processed += current_chunk;
    }
    
    // Copy result if found
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
