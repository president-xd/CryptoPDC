#include "cryptopdc/cuda/hash/sha224_kernel.cuh"
#include <cuda_runtime.h>

namespace cryptopdc {
namespace cuda {
namespace hash {

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

__constant__ uint32_t d_sha224_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ void device_sha224(const uint8_t* input, size_t len, uint8_t* output) {
    // SHA-224 initial values
    uint32_t h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939;
    uint32_t h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;
    
    uint8_t block[64];
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (size_t i = 0; i < len && i < 55; i++) block[i] = input[i];
    block[len] = 0x80;
    
    uint64_t bits = len * 8;
    for (int i = 0; i < 8; i++) {
        block[56 + i] = (bits >> (56 - i * 8)) & 0xFF;
    }
    
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    }
    
    uint32_t a = h0, b = h1, c = h2, d = h3;
    uint32_t e = h4, f = h5, g = h6, h = h7;
    
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + d_sha224_k[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    h0 += a; h1 += b; h2 += c; h3 += d;
    h4 += e; h5 += f; h6 += g; h7 += h;
    
    // Output first 28 bytes (224 bits)
    for (int i = 0; i < 4; i++) output[i] = (h0 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[4+i] = (h1 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[8+i] = (h2 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[12+i] = (h3 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[16+i] = (h4 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[20+i] = (h5 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[24+i] = (h6 >> (24 - i * 8)) & 0xFF;
}

__global__ void sha224_crack_kernel(
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
    device_sha224((const uint8_t*)word, len, hash);
    
    bool match = true;
    for (int i = 0; i < 28 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

void launch_sha224_crack(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index,
    int blocks,
    int threads_per_block
) {
    sha224_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

} // namespace hash
} // namespace cuda
} // namespace cryptopdc
