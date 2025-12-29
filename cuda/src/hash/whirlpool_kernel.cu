#include "cryptopdc/cuda/hash/whirlpool_kernel.cuh"
#include <cuda_runtime.h>

namespace cryptopdc {
namespace cuda {
namespace hash {

// Whirlpool S-box in constant memory
__constant__ uint8_t d_SBOX[256] = {
    0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52,
    0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C, 0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57,
    0x15, 0x77, 0x37, 0xE5, 0x9F, 0xF0, 0x4A, 0xDA, 0x58, 0xC9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85,
    0xBD, 0x5D, 0x10, 0xF4, 0xCB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7D, 0x95, 0xD8,
    0xFB, 0xEE, 0x7C, 0x66, 0xDD, 0x17, 0x47, 0x9E, 0xCA, 0x2D, 0xBF, 0x07, 0xAD, 0x5A, 0x83, 0x33,
    0x63, 0x02, 0xAA, 0x71, 0xC8, 0x19, 0x49, 0xD9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0,
    0xE9, 0x0F, 0xD5, 0x80, 0xBE, 0xCD, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE,
    0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xC3, 0xEC, 0xDB, 0xA1, 0x8D, 0x3D,
    0x97, 0x00, 0xCF, 0x2B, 0x76, 0x82, 0xD6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3, 0x30, 0xEF,
    0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xC0, 0xDE, 0x1C, 0xFD, 0x4D, 0x92, 0x75, 0x06, 0x8A,
    0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xD4, 0xA8, 0x96, 0xF9, 0xC5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4C,
    0x5E, 0x78, 0x38, 0x8C, 0xD1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9C, 0x1E, 0x43, 0xC7, 0xFC, 0x04,
    0x51, 0x99, 0x6D, 0x0D, 0xFA, 0xDF, 0x7E, 0x24, 0x3B, 0xAB, 0xCE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB,
    0x3C, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2C, 0xD3, 0xE7, 0x6E, 0xC4, 0x03, 0x56, 0x44, 0x7F, 0xA9,
    0x2A, 0xBB, 0xC1, 0x53, 0xDC, 0x0B, 0x9D, 0x6C, 0x31, 0x74, 0xF6, 0x46, 0xAC, 0x89, 0x14, 0xE1,
    0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xD0, 0xED, 0xCC, 0x42, 0x98, 0xA4, 0x28, 0x5C, 0xF8, 0x86
};

__constant__ uint64_t d_RC[10] = {
    0x1823c6e887b8014fULL, 0x36a6d2f5796f9152ULL, 0x60bc9b8ea30c7b35ULL, 0x1de0d7c22e4bfe57ULL,
    0x157737e59ff04adaULL, 0x58c9290ab1a06b85ULL, 0xbd5d10f4cb3e0567ULL, 0xe427418ba77d95d8ULL,
    0xfbee7c66dd17479eULL, 0xca2dbf07ad5a8333ULL
};

__constant__ uint8_t d_MDS[8] = {0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09};

__device__ uint8_t device_gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        uint8_t hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1D;
        b >>= 1;
    }
    return result;
}

__device__ void device_whirlpool_transform(uint64_t* hash, const uint8_t* block) {
    uint64_t K[8], state[8], L[8];
    
    for (int i = 0; i < 8; i++) {
        K[i] = hash[i];
        state[i] = 0;
        for (int j = 0; j < 8; j++) {
            state[i] |= ((uint64_t)block[i * 8 + j]) << (56 - j * 8);
        }
        state[i] ^= K[i];
    }
    
    for (int r = 0; r < 10; r++) {
        // Key schedule with S-box and MDS
        for (int i = 0; i < 8; i++) {
            L[i] = 0;
            for (int t = 0; t < 8; t++) {
                int idx = (i + t) % 8;
                uint8_t s = d_SBOX[(K[idx] >> (56 - t * 8)) & 0xFF];
                for (int k = 0; k < 8; k++) {
                    L[i] ^= ((uint64_t)device_gf_mul(s, d_MDS[(t + k) % 8])) << (56 - k * 8);
                }
            }
        }
        L[0] ^= d_RC[r];
        for (int i = 0; i < 8; i++) K[i] = L[i];
        
        // State transformation
        for (int i = 0; i < 8; i++) {
            L[i] = K[i];
            for (int t = 0; t < 8; t++) {
                int idx = (i + t) % 8;
                uint8_t s = d_SBOX[(state[idx] >> (56 - t * 8)) & 0xFF];
                for (int k = 0; k < 8; k++) {
                    L[i] ^= ((uint64_t)device_gf_mul(s, d_MDS[(t + k) % 8])) << (56 - k * 8);
                }
            }
        }
        for (int i = 0; i < 8; i++) state[i] = L[i];
    }
    
    // Feedforward
    for (int i = 0; i < 8; i++) {
        uint64_t block_word = 0;
        for (int j = 0; j < 8; j++) {
            block_word |= ((uint64_t)block[i * 8 + j]) << (56 - j * 8);
        }
        hash[i] ^= state[i] ^ block_word;
    }
}

__device__ void device_whirlpool(const uint8_t* input, size_t len, uint8_t* output) {
    uint64_t hash[8] = {0};
    
    // Process complete blocks
    size_t processed = 0;
    while (processed + 64 <= len) {
        device_whirlpool_transform(hash, input + processed);
        processed += 64;
    }
    
    // Padding
    uint8_t block[64] = {0};
    size_t remaining = len - processed;
    for (size_t i = 0; i < remaining; i++) block[i] = input[processed + i];
    block[remaining] = 0x80;
    
    if (remaining >= 32) {
        device_whirlpool_transform(hash, block);
        for (int i = 0; i < 64; i++) block[i] = 0;
    }
    
    uint64_t bits = len * 8;
    for (int i = 0; i < 8; i++) {
        block[63 - i] = (bits >> (i * 8)) & 0xFF;
    }
    device_whirlpool_transform(hash, block);
    
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = (hash[i] >> (56 - j * 8)) & 0xFF;
        }
    }
}

__global__ void whirlpool_crack_kernel(
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
    device_whirlpool((const uint8_t*)word, len, hash);
    
    bool match = true;
    for (int i = 0; i < 64 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

void launch_whirlpool_crack(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index,
    int blocks,
    int threads_per_block
) {
    whirlpool_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

} // namespace hash
} // namespace cuda
} // namespace cryptopdc
