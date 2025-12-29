#include "cryptopdc/cuda/hash/sha512_kernel.cuh"
#include "cryptopdc/cuda/common.cuh"
#include <cstring>

namespace cryptopdc {
namespace cuda {
namespace hash {

// SHA-512 constants - first 64 bits of fractional parts of cube roots of first 80 primes
__constant__ uint64_t d_sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// SHA-512 initial hash values
__constant__ uint64_t d_sha512_h0[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

// 64-bit right rotate
__device__ __forceinline__ uint64_t rotr64(uint64_t x, uint32_t n) {
    return (x >> n) | (x << (64 - n));
}

// SHA-512 helper functions
__device__ __forceinline__ uint64_t ch512(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

__device__ __forceinline__ uint64_t maj512(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ uint64_t Sigma0_512(uint64_t x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

__device__ __forceinline__ uint64_t Sigma1_512(uint64_t x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

__device__ __forceinline__ uint64_t sigma0_512(uint64_t x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

__device__ __forceinline__ uint64_t sigma1_512(uint64_t x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

// Device SHA-512 computation - fully implemented on GPU
__device__ void sha512_hash_device(const uint8_t* input, size_t length, uint8_t* output) {
    // Initialize hash values
    uint64_t h[8];
    for (int i = 0; i < 8; i++) {
        h[i] = d_sha512_h0[i];
    }
    
    // Message buffer (256 bytes for typical password cracking - handles up to ~111 bytes input)
    uint8_t msg[256];
    
    // Calculate padded message length
    // SHA-512 uses 128-byte (1024-bit) blocks
    // Padding: message + 1 bit + zeros + 128-bit length
    size_t new_len = ((((length + 16) / 128) + 1) * 128) - 16;
    
    // Copy input to message buffer
    for (size_t i = 0; i < length && i < 239; i++) {
        msg[i] = input[i];
    }
    
    // Append '1' bit (0x80)
    msg[length] = 0x80;
    
    // Padding with zeros
    for (size_t i = length + 1; i < new_len; i++) {
        msg[i] = 0;
    }
    
    // Append original message length in bits as 128-bit big-endian
    // Upper 64 bits (0 for reasonable message lengths)
    for (int i = 0; i < 8; i++) {
        msg[new_len + i] = 0;
    }
    // Lower 64 bits
    uint64_t bits_len = length * 8;
    msg[new_len + 8] = (bits_len >> 56) & 0xFF;
    msg[new_len + 9] = (bits_len >> 48) & 0xFF;
    msg[new_len + 10] = (bits_len >> 40) & 0xFF;
    msg[new_len + 11] = (bits_len >> 32) & 0xFF;
    msg[new_len + 12] = (bits_len >> 24) & 0xFF;
    msg[new_len + 13] = (bits_len >> 16) & 0xFF;
    msg[new_len + 14] = (bits_len >> 8) & 0xFF;
    msg[new_len + 15] = bits_len & 0xFF;
    
    // Process message in 1024-bit (128-byte) chunks
    for (size_t offset = 0; offset < new_len + 16; offset += 128) {
        // Message schedule array
        uint64_t w[80];
        
        // Break chunk into sixteen 64-bit big-endian words
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint64_t)msg[offset + i * 8] << 56) |
                   ((uint64_t)msg[offset + i * 8 + 1] << 48) |
                   ((uint64_t)msg[offset + i * 8 + 2] << 40) |
                   ((uint64_t)msg[offset + i * 8 + 3] << 32) |
                   ((uint64_t)msg[offset + i * 8 + 4] << 24) |
                   ((uint64_t)msg[offset + i * 8 + 5] << 16) |
                   ((uint64_t)msg[offset + i * 8 + 6] << 8) |
                   ((uint64_t)msg[offset + i * 8 + 7]);
        }
        
        // Extend the sixteen 64-bit words into eighty 64-bit words
        for (int i = 16; i < 80; i++) {
            w[i] = sigma1_512(w[i - 2]) + w[i - 7] + sigma0_512(w[i - 15]) + w[i - 16];
        }
        
        // Initialize working variables
        uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
        
        // Compression function main loop - 80 rounds
        for (int i = 0; i < 80; i++) {
            uint64_t t1 = hh + Sigma1_512(e) + ch512(e, f, g) + d_sha512_k[i] + w[i];
            uint64_t t2 = Sigma0_512(a) + maj512(a, b, c);
            
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
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    
    // Produce the final hash value (big-endian) - 512 bits = 64 bytes
    for (int i = 0; i < 8; i++) {
        output[i * 8] = (h[i] >> 56) & 0xFF;
        output[i * 8 + 1] = (h[i] >> 48) & 0xFF;
        output[i * 8 + 2] = (h[i] >> 40) & 0xFF;
        output[i * 8 + 3] = (h[i] >> 32) & 0xFF;
        output[i * 8 + 4] = (h[i] >> 24) & 0xFF;
        output[i * 8 + 5] = (h[i] >> 16) & 0xFF;
        output[i * 8 + 6] = (h[i] >> 8) & 0xFF;
        output[i * 8 + 7] = h[i] & 0xFF;
    }
}

__global__ void sha512_crack_kernel(
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
    
    // Compute SHA-512 hash on GPU
    uint8_t hash[64];
    sha512_hash_device(reinterpret_cast<const uint8_t*>(candidate), key_length, hash);
    
    // Compare with target hash (64 bytes for SHA-512)
    if (memcmp_device(hash, target_hash, 64)) {
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

cudaError_t launch_sha512_crack(
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
    
    CUDA_CHECK(cudaMalloc(&d_target_hash, 64));  // SHA-512 = 64 bytes
    CUDA_CHECK(cudaMalloc(&d_charset, charset_len));
    CUDA_CHECK(cudaMalloc(&d_result_key, 64));
    CUDA_CHECK(cudaMalloc(&d_found_flag, sizeof(int)));
    
    // Copy data to device
    CUDA_CHECK(cudaMemcpy(d_target_hash, target_hash, 64, cudaMemcpyHostToDevice));
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
        sha512_crack_kernel<<<blocks, threads_per_block>>>(
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
