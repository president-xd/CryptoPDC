#include "cryptopdc/cuda/hash/sha3_kernel.cuh"
#include <cuda_runtime.h>

namespace cryptopdc {
namespace cuda {
namespace hash {

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// Keccak round constants
__constant__ uint64_t d_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Device Keccak-f[1600] permutation
__device__ void device_keccak_f1600(uint64_t state[25]) {
    const int rotations[5][5] = {
        { 0,  1, 62, 28, 27},
        {36, 44,  6, 55, 20},
        { 3, 10, 43, 25, 39},
        {41, 45, 15, 21,  8},
        {18,  2, 61, 56, 14}
    };
    
    for (int round = 0; round < 24; round++) {
        // Theta
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ ROTL64(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }
        
        // Rho and Pi
        uint64_t B[25];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                B[y + 5 * ((2 * x + 3 * y) % 5)] = ROTL64(state[x + 5 * y], rotations[y][x]);
            }
        }
        
        // Chi
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                state[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);
            }
        }
        
        // Iota
        state[0] ^= d_RC[round];
    }
}

// Device SHA3 hash function (generic for all variants)
__device__ void device_sha3(const uint8_t* input, size_t len, uint8_t* output, size_t output_len, size_t rate_bits) {
    uint64_t state[25] = {0};
    size_t rate_bytes = rate_bits / 8;
    
    // Absorb phase - simplified for short inputs
    size_t absorbed = 0;
    while (absorbed + rate_bytes <= len) {
        for (size_t i = 0; i < rate_bytes / 8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++) {
                lane |= ((uint64_t)input[absorbed + i * 8 + j]) << (j * 8);
            }
            state[i] ^= lane;
        }
        device_keccak_f1600(state);
        absorbed += rate_bytes;
    }
    
    // Pad remaining
    uint8_t padded[200] = {0};
    size_t remaining = len - absorbed;
    for (size_t i = 0; i < remaining; i++) {
        padded[i] = input[absorbed + i];
    }
    padded[remaining] = 0x06;  // SHA3 domain separator
    padded[rate_bytes - 1] |= 0x80;
    
    for (size_t i = 0; i < rate_bytes / 8; i++) {
        uint64_t lane = 0;
        for (int j = 0; j < 8; j++) {
            lane |= ((uint64_t)padded[i * 8 + j]) << (j * 8);
        }
        state[i] ^= lane;
    }
    device_keccak_f1600(state);
    
    // Squeeze phase
    for (size_t i = 0; i < output_len; i++) {
        output[i] = (state[i / 8] >> ((i % 8) * 8)) & 0xFF;
    }
}

// SHA3-224 kernel
__global__ void sha3_224_crack_kernel(
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
    
    uint8_t hash[28];
    device_sha3((const uint8_t*)word, len, hash, 28, 1152);
    
    bool match = true;
    for (int i = 0; i < 28 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// SHA3-256 kernel
__global__ void sha3_256_crack_kernel(
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
    device_sha3((const uint8_t*)word, len, hash, 32, 1088);
    
    bool match = true;
    for (int i = 0; i < 32 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// SHA3-384 kernel
__global__ void sha3_384_crack_kernel(
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
    
    uint8_t hash[48];
    device_sha3((const uint8_t*)word, len, hash, 48, 832);
    
    bool match = true;
    for (int i = 0; i < 48 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// SHA3-512 kernel
__global__ void sha3_512_crack_kernel(
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
    device_sha3((const uint8_t*)word, len, hash, 64, 576);
    
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
void launch_sha3_224_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    sha3_224_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

void launch_sha3_256_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    sha3_256_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

void launch_sha3_384_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    sha3_384_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

void launch_sha3_512_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    sha3_512_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

} // namespace hash
} // namespace cuda
} // namespace cryptopdc
