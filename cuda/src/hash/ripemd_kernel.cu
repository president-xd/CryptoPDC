#include "cryptopdc/cuda/hash/ripemd_kernel.cuh"
#include <cuda_runtime.h>

namespace cryptopdc {
namespace cuda {
namespace hash {

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z) (((x) | ~(y)) ^ (z))
#define I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z) ((x) ^ ((y) | ~(z)))

// RIPEMD-160 constants in constant memory
__constant__ uint32_t d_RMD160_K[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
__constant__ uint32_t d_RMD160_KK[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};

__constant__ int d_RMD160_R[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

__constant__ int d_RMD160_RR[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

__constant__ int d_RMD160_S[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

__constant__ int d_RMD160_SS[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

// RIPEMD-128 constants
__constant__ uint32_t d_RMD128_K[4] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC};
__constant__ uint32_t d_RMD128_KK[4] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x00000000};

__constant__ int d_RMD128_R[64] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
};

__constant__ int d_RMD128_RR[64] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
};

__constant__ int d_RMD128_S[64] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
};

__constant__ int d_RMD128_SS[64] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
};

// Device function for RIPEMD-160
__device__ void device_ripemd160(const uint8_t* input, size_t len, uint8_t* output) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    
    uint8_t block[64];
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (size_t i = 0; i < len && i < 55; i++) block[i] = input[i];
    block[len] = 0x80;
    uint64_t bits = len * 8;
    for (int i = 0; i < 8; i++) block[56 + i] = (bits >> (i * 8)) & 0xFF;
    
    uint32_t* X = (uint32_t*)block;
    
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    uint32_t aa = h0, bb = h1, cc = h2, dd = h3, ee = h4;
    
    for (int j = 0; j < 80; j++) {
        uint32_t f, ff, t;
        int jj = j / 16;
        
        switch (jj) {
            case 0: f = F(b, c, d); ff = J(bb, cc, dd); break;
            case 1: f = G(b, c, d); ff = I(bb, cc, dd); break;
            case 2: f = H(b, c, d); ff = H(bb, cc, dd); break;
            case 3: f = I(b, c, d); ff = G(bb, cc, dd); break;
            default: f = J(b, c, d); ff = F(bb, cc, dd); break;
        }
        
        t = ROTL32(a + f + X[d_RMD160_R[j]] + d_RMD160_K[jj], d_RMD160_S[j]) + e;
        a = e; e = d; d = ROTL32(c, 10); c = b; b = t;
        
        t = ROTL32(aa + ff + X[d_RMD160_RR[j]] + d_RMD160_KK[jj], d_RMD160_SS[j]) + ee;
        aa = ee; ee = dd; dd = ROTL32(cc, 10); cc = bb; bb = t;
    }
    
    uint32_t t = h1 + c + dd;
    h1 = h2 + d + ee; h2 = h3 + e + aa; h3 = h4 + a + bb; h4 = h0 + b + cc; h0 = t;
    
    for (int i = 0; i < 4; i++) { output[i] = (h0 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[4+i] = (h1 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[8+i] = (h2 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[12+i] = (h3 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[16+i] = (h4 >> (i*8)) & 0xFF; }
}

// Device function for RIPEMD-128
__device__ void device_ripemd128(const uint8_t* input, size_t len, uint8_t* output) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476;
    
    uint8_t block[64];
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (size_t i = 0; i < len && i < 55; i++) block[i] = input[i];
    block[len] = 0x80;
    uint64_t bits = len * 8;
    for (int i = 0; i < 8; i++) block[56 + i] = (bits >> (i * 8)) & 0xFF;
    
    uint32_t* X = (uint32_t*)block;
    
    uint32_t a = h0, b = h1, c = h2, d = h3;
    uint32_t aa = h0, bb = h1, cc = h2, dd = h3;
    
    for (int j = 0; j < 64; j++) {
        uint32_t f, ff, t;
        int jj = j / 16;
        
        switch (jj) {
            case 0: f = F(b, c, d); ff = I(bb, cc, dd); break;
            case 1: f = G(b, c, d); ff = H(bb, cc, dd); break;
            case 2: f = H(b, c, d); ff = G(bb, cc, dd); break;
            default: f = I(b, c, d); ff = F(bb, cc, dd); break;
        }
        
        t = ROTL32(a + f + X[d_RMD128_R[j]] + d_RMD128_K[jj], d_RMD128_S[j]);
        a = d; d = c; c = b; b = t;
        
        t = ROTL32(aa + ff + X[d_RMD128_RR[j]] + d_RMD128_KK[jj], d_RMD128_SS[j]);
        aa = dd; dd = cc; cc = bb; bb = t;
    }
    
    uint32_t t = h1 + c + dd;
    h1 = h2 + d + aa; h2 = h3 + a + bb; h3 = h0 + b + cc; h0 = t;
    
    for (int i = 0; i < 4; i++) { output[i] = (h0 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[4+i] = (h1 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[8+i] = (h2 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[12+i] = (h3 >> (i*8)) & 0xFF; }
}

// Device function for RIPEMD-256
__device__ void device_ripemd256(const uint8_t* input, size_t len, uint8_t* output) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476;
    uint32_t h4 = 0x76543210, h5 = 0xFEDCBA98, h6 = 0x89ABCDEF, h7 = 0x01234567;
    
    uint8_t block[64];
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (size_t i = 0; i < len && i < 55; i++) block[i] = input[i];
    block[len] = 0x80;
    uint64_t bits = len * 8;
    for (int i = 0; i < 8; i++) block[56 + i] = (bits >> (i * 8)) & 0xFF;
    
    uint32_t* X = (uint32_t*)block;
    
    uint32_t a = h0, b = h1, c = h2, d = h3;
    uint32_t aa = h4, bb = h5, cc = h6, dd = h7;
    uint32_t t;
    
    for (int j = 0; j < 64; j++) {
        uint32_t f, ff;
        int jj = j / 16;
        
        switch (jj) {
            case 0: f = F(b, c, d); ff = I(bb, cc, dd); break;
            case 1: f = G(b, c, d); ff = H(bb, cc, dd); break;
            case 2: f = H(b, c, d); ff = G(bb, cc, dd); break;
            default: f = I(b, c, d); ff = F(bb, cc, dd); break;
        }
        
        t = ROTL32(a + f + X[d_RMD128_R[j]] + d_RMD128_K[jj], d_RMD128_S[j]);
        a = d; d = c; c = b; b = t;
        
        t = ROTL32(aa + ff + X[d_RMD128_RR[j]] + d_RMD128_KK[jj], d_RMD128_SS[j]);
        aa = dd; dd = cc; cc = bb; bb = t;
        
        if (j == 15) { t = a; a = aa; aa = t; }
        else if (j == 31) { t = b; b = bb; bb = t; }
        else if (j == 47) { t = c; c = cc; cc = t; }
        else if (j == 63) { t = d; d = dd; dd = t; }
    }
    
    h0 += a; h1 += b; h2 += c; h3 += d;
    h4 += aa; h5 += bb; h6 += cc; h7 += dd;
    
    for (int i = 0; i < 4; i++) { output[i] = (h0 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[4+i] = (h1 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[8+i] = (h2 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[12+i] = (h3 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[16+i] = (h4 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[20+i] = (h5 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[24+i] = (h6 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[28+i] = (h7 >> (i*8)) & 0xFF; }
}

// Device function for RIPEMD-320
__device__ void device_ripemd320(const uint8_t* input, size_t len, uint8_t* output) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    uint32_t h5 = 0x76543210, h6 = 0xFEDCBA98, h7 = 0x89ABCDEF, h8 = 0x01234567, h9 = 0x3C2D1E0F;
    
    uint8_t block[64];
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (size_t i = 0; i < len && i < 55; i++) block[i] = input[i];
    block[len] = 0x80;
    uint64_t bits = len * 8;
    for (int i = 0; i < 8; i++) block[56 + i] = (bits >> (i * 8)) & 0xFF;
    
    uint32_t* X = (uint32_t*)block;
    
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    uint32_t aa = h5, bb = h6, cc = h7, dd = h8, ee = h9;
    
    for (int j = 0; j < 80; j++) {
        uint32_t f, ff, t;
        int jj = j / 16;
        
        switch (jj) {
            case 0: f = F(b, c, d); ff = J(bb, cc, dd); break;
            case 1: f = G(b, c, d); ff = I(bb, cc, dd); break;
            case 2: f = H(b, c, d); ff = H(bb, cc, dd); break;
            case 3: f = I(b, c, d); ff = G(bb, cc, dd); break;
            default: f = J(b, c, d); ff = F(bb, cc, dd); break;
        }
        
        t = ROTL32(a + f + X[d_RMD160_R[j]] + d_RMD160_K[jj], d_RMD160_S[j]) + e;
        a = e; e = d; d = ROTL32(c, 10); c = b; b = t;
        
        t = ROTL32(aa + ff + X[d_RMD160_RR[j]] + d_RMD160_KK[jj], d_RMD160_SS[j]) + ee;
        aa = ee; ee = dd; dd = ROTL32(cc, 10); cc = bb; bb = t;
        
        if (j == 15) { t = b; b = bb; bb = t; }
        else if (j == 31) { t = d; d = dd; dd = t; }
        else if (j == 47) { t = a; a = aa; aa = t; }
        else if (j == 63) { t = c; c = cc; cc = t; }
        else if (j == 79) { t = e; e = ee; ee = t; }
    }
    
    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    h5 += aa; h6 += bb; h7 += cc; h8 += dd; h9 += ee;
    
    for (int i = 0; i < 4; i++) { output[i] = (h0 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[4+i] = (h1 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[8+i] = (h2 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[12+i] = (h3 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[16+i] = (h4 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[20+i] = (h5 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[24+i] = (h6 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[28+i] = (h7 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[32+i] = (h8 >> (i*8)) & 0xFF; }
    for (int i = 0; i < 4; i++) { output[36+i] = (h9 >> (i*8)) & 0xFF; }
}

// RIPEMD-128 kernel
__global__ void ripemd128_crack_kernel(
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
    device_ripemd128((const uint8_t*)word, len, hash);
    
    bool match = true;
    for (int i = 0; i < 16 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// RIPEMD-160 kernel
__global__ void ripemd160_crack_kernel(
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
    
    uint8_t hash[20];
    device_ripemd160((const uint8_t*)word, len, hash);
    
    bool match = true;
    for (int i = 0; i < 20 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// RIPEMD-256 kernel
__global__ void ripemd256_crack_kernel(
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
    device_ripemd256((const uint8_t*)word, len, hash);
    
    bool match = true;
    for (int i = 0; i < 32 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// RIPEMD-320 kernel
__global__ void ripemd320_crack_kernel(
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
    
    uint8_t hash[40];
    device_ripemd320((const uint8_t*)word, len, hash);
    
    bool match = true;
    for (int i = 0; i < 40 && match; i++) {
        if (hash[i] != target_hash[i]) match = false;
    }
    
    if (match) {
        *found = 1;
        *found_index = idx;
    }
}

// Launch functions
void launch_ripemd128_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    ripemd128_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

void launch_ripemd160_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    ripemd160_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

void launch_ripemd256_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    ripemd256_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

void launch_ripemd320_crack(
    const uint8_t* target_hash, const char* wordlist, const size_t* word_offsets,
    size_t num_words, int* found, size_t* found_index, int blocks, int threads_per_block
) {
    ripemd320_crack_kernel<<<blocks, threads_per_block>>>(
        target_hash, wordlist, word_offsets, num_words, found, found_index
    );
}

} // namespace hash
} // namespace cuda
} // namespace cryptopdc
