#include "cryptopdc/cuda/hash/md6_kernel.cuh"
#include <cuda_runtime.h>

namespace cryptopdc {
namespace cuda {
namespace hash {

// MD6 Q constant
__constant__ uint64_t d_MD6_Q[15] = {
    0x7311c2812425cfa0ULL, 0x6432286434aac8e7ULL, 0xb60450e9ef68b7c1ULL,
    0xe8fb23908d9f06f1ULL, 0xdd2e76cba691e5bfULL, 0x0cd0d63b2c30bc41ULL,
    0x1f8ccf6823058f8aULL, 0x54e5ed5b88e3775dULL, 0x4ad12aae0a6d6031ULL,
    0x3e7f16bb88222e0dULL, 0x8af8671d3fb50c2cULL, 0x995ad1178bd25c31ULL,
    0xc878c1dd04c4b633ULL, 0x3b72066c7a1552acULL, 0x0d6f3522631effcbULL
};

__constant__ int d_MD6_S[16] = {
    10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12
};

// Device MD6 compression function (simplified)
__device__ void device_md6_compress(uint64_t* C, const uint64_t* N, int r) {
    const int n = 89;
    const int c = 16;
    
    uint64_t A[89 + 16 * 80];  // For 80 rounds max
    for (int i = 0; i < n; i++) A[i] = N[i];
    
    int t0 = 17, t1 = 18, t2 = 21, t3 = 31, t4 = 67;
    
    for (int j = 0; j < r * c; j++) {
        int i = n + j;
        uint64_t x = A[i - n] ^ A[i - t0];
        x ^= (A[i - t1] & A[i - t2]);
        x ^= (A[i - t3] & A[i - t4]);
        x ^= (x >> d_MD6_S[j % 16]);
        A[i] = x ^ d_MD6_Q[j % 15];
    }
    
    for (int i = 0; i < c; i++) {
        C[i] = A[n + r * c - c + i];
    }
}

// Device MD6 hash function
__device__ void device_md6(const uint8_t* input, size_t len, uint8_t* output, size_t d) {
    const int r = 80;
    uint64_t N[89] = {0};
    
    // Copy Q constants
    for (int i = 0; i < 15; i++) N[i] = d_MD6_Q[i];
    
    // Set U (unique ID)
    N[23] = ((uint64_t)r << 48) | ((uint64_t)4 << 24) | ((uint64_t)64 << 16) | (uint64_t)d;
    
    // Copy message
    for (size_t i = 0; i < len && i < 512; i++) {
        int word_idx = 25 + (i / 8);
        int byte_pos = i % 8;
        N[word_idx] |= ((uint64_t)input[i]) << (byte_pos * 8);
    }
    
    // Add padding
    if (len < 512) {
        int pad_idx = 25 + (len / 8);
        int pad_bit = len % 8;
        N[pad_idx] |= ((uint64_t)0x80) << (pad_bit * 8);
    }
    
    uint64_t C[16];
    device_md6_compress(C, N, r);
    
    size_t out_bytes = d / 8;
    for (size_t i = 0; i < out_bytes && i < 64; i++) {
        output[i] = (C[16 - (out_bytes / 8) + i / 8] >> ((i % 8) * 8)) & 0xFF;
    }
}

// MD6-128 kernel
__global__ void md6_128_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
) {
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_words || *found) return;
    
    const char* word = wordlist + word_offsets[idx];
    size_t len = word_offsets[idx + 1] - word_offsets[idx] - 1;
    
    uint8_t hash[16];
    device_md6((const uint8_t*)word, len, hash, 128);
    
    bool match = true;
    for (int i = 0; i < 16 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// MD6-256 kernel
__global__ void md6_256_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
) {
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_words || *found) return;
    
    const char* word = wordlist + word_offsets[idx];
    size_t len = word_offsets[idx + 1] - word_offsets[idx] - 1;
    
    uint8_t hash[32];
    device_md6((const uint8_t*)word, len, hash, 256);
    
    bool match = true;
    for (int i = 0; i < 32 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// MD6-512 kernel
__global__ void md6_512_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
) {
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_words || *found) return;
    
    const char* word = wordlist + word_offsets[idx];
    size_t len = word_offsets[idx + 1] - word_offsets[idx] - 1;
    
    uint8_t hash[64];
    device_md6((const uint8_t*)word, len, hash, 512);
    
    bool match = true;
    for (int i = 0; i < 64 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// Launch functions
void launch_md6_128_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    md6_128_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

void launch_md6_256_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    md6_256_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

void launch_md6_512_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    md6_512_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

} // namespace hash
} // namespace cuda
} // namespace cryptopdc
