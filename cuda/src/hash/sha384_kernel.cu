#include "cryptopdc/cuda/hash/sha384_kernel.cuh"
#include <cuda_runtime.h>

namespace cryptopdc {
namespace cuda {
namespace hash {

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_64(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define EP1_64(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SIG0_64(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SIG1_64(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

__constant__ uint64_t d_sha384_k[80] = {
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

__device__ void device_sha384(const uint8_t* input, size_t len, uint8_t* output) {
    // SHA-384 initial values
    uint64_t h0 = 0xcbbb9d5dc1059ed8ULL, h1 = 0x629a292a367cd507ULL;
    uint64_t h2 = 0x9159015a3070dd17ULL, h3 = 0x152fecd8f70e5939ULL;
    uint64_t h4 = 0x67332667ffc00b31ULL, h5 = 0x8eb44a8768581511ULL;
    uint64_t h6 = 0xdb0c2e0d64f98fa7ULL, h7 = 0x47b5481dbefa4fa4ULL;
    
    uint8_t block[128];
    for (int i = 0; i < 128; i++) block[i] = 0;
    for (size_t i = 0; i < len && i < 111; i++) block[i] = input[i];
    block[len] = 0x80;
    
    uint64_t bits = len * 8;
    for (int i = 0; i < 8; i++) {
        block[120 + i] = (bits >> (56 - i * 8)) & 0xFF;
    }
    
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint64_t)block[i*8] << 56) | ((uint64_t)block[i*8+1] << 48) |
               ((uint64_t)block[i*8+2] << 40) | ((uint64_t)block[i*8+3] << 32) |
               ((uint64_t)block[i*8+4] << 24) | ((uint64_t)block[i*8+5] << 16) |
               ((uint64_t)block[i*8+6] << 8) | (uint64_t)block[i*8+7];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = SIG1_64(w[i-2]) + w[i-7] + SIG0_64(w[i-15]) + w[i-16];
    }
    
    uint64_t a = h0, b = h1, c = h2, d = h3;
    uint64_t e = h4, f = h5, g = h6, h = h7;
    
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + EP1_64(e) + CH64(e, f, g) + d_sha384_k[i] + w[i];
        uint64_t t2 = EP0_64(a) + MAJ64(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    h0 += a; h1 += b; h2 += c; h3 += d;
    h4 += e; h5 += f; h6 += g; h7 += h;
    
    // Output first 48 bytes (384 bits)
    for (int i = 0; i < 8; i++) output[i] = (h0 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[8+i] = (h1 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[16+i] = (h2 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[24+i] = (h3 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[32+i] = (h4 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[40+i] = (h5 >> (56 - i * 8)) & 0xFF;
}

__global__ void sha384_crack_kernel(
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
    device_sha384((const uint8_t*)word, len, hash);
    
    bool match = true;
    for (int i = 0; i < 48 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

void launch_sha384_crack(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index,
    int blocks,
    int threads_per_block
) {
    sha384_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

} // namespace hash
} // namespace cuda
} // namespace cryptopdc
