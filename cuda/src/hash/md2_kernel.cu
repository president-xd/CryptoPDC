#include "cryptopdc/cuda/hash/md2_kernel.cuh"
#include "cryptopdc/cuda/common.cuh"
#include <cstring>

namespace cryptopdc {
namespace cuda {
namespace hash {

__constant__ uint8_t d_md2_s[256] = {
     41, 46, 67, 201, 162, 216, 124,  1,  61, 54,  84, 161, 236, 240,  6,  19,
     98, 167,  5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
     30, 155,  87, 60, 253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229, 18,
    190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
    169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16,  137,  11,  34, 95,  33,
    128, 127,  93, 154,  90, 144,  50,  39, 53,  62, 204, 231, 191, 247, 151,  3,
    255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
     79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,  4, 241,
     69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,  2,
     27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126, 15,
     85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
     44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77, 82,
    106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
    120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
    242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
     49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131, 20
};

__device__ void md2_hash_device(const uint8_t* input, size_t length, uint8_t* output) {
    uint8_t X[48];
    uint8_t C[16];
    uint8_t padded[64]; // Max 48 bytes for passwords + 16 checksum
    
    for (int i = 0; i < 48; i++) X[i] = 0;
    for (int i = 0; i < 16; i++) C[i] = 0;
    
    // Padding
    size_t padLen = 16 - (length % 16);
    size_t paddedLen = length + padLen;
    
    for (size_t i = 0; i < length; i++) padded[i] = input[i];
    for (size_t i = length; i < paddedLen; i++) padded[i] = (uint8_t)padLen;
    
    // Compute checksum
    uint8_t L = 0;
    for (size_t i = 0; i < paddedLen; i += 16) {
        for (int j = 0; j < 16; j++) {
            C[j] ^= d_md2_s[padded[i + j] ^ L];
            L = C[j];
        }
    }
    
    // Append checksum
    for (int j = 0; j < 16; j++) padded[paddedLen + j] = C[j];
    paddedLen += 16;
    
    // Process blocks
    for (size_t i = 0; i < paddedLen; i += 16) {
        for (int j = 0; j < 16; j++) {
            X[16 + j] = padded[i + j];
            X[32 + j] = X[j] ^ padded[i + j];
        }
        
        uint8_t t = 0;
        for (int round = 0; round < 18; round++) {
            for (int j = 0; j < 48; j++) {
                X[j] ^= d_md2_s[t];
                t = X[j];
            }
            t = (t + round) & 0xFF;
        }
    }
    
    for (int i = 0; i < 16; i++) output[i] = X[i];
}

__global__ void md2_crack_kernel(
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
    
    if (idx >= count || *found_flag) return;
    
    uint64_t key_index = start_index + idx;
    char key[64];
    index_to_key_device(key_index, key, charset, charset_len, key_length);
    
    uint8_t computed_hash[16];
    md2_hash_device((const uint8_t*)key, key_length, computed_hash);
    
    if (memcmp_device(computed_hash, target_hash, 16)) {
        if (atomicCAS(found_flag, 0, 1) == 0) {
            for (int i = 0; i < key_length; i++) {
                result_key[i] = key[i];
            }
            result_key[key_length] = '\0';
        }
    }
}

cudaError_t launch_md2_crack(
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
    cudaError_t err = cudaSetDevice(device_id);
    if (err != cudaSuccess) return err;
    
    uint8_t* d_target;
    char* d_charset;
    char* d_result;
    int* d_found;
    
    err = cudaMalloc(&d_target, 16);
    if (err != cudaSuccess) return err;
    
    err = cudaMalloc(&d_charset, charset_len);
    if (err != cudaSuccess) { cudaFree(d_target); return err; }
    
    err = cudaMalloc(&d_result, 64);
    if (err != cudaSuccess) { cudaFree(d_target); cudaFree(d_charset); return err; }
    
    err = cudaMalloc(&d_found, sizeof(int));
    if (err != cudaSuccess) { cudaFree(d_target); cudaFree(d_charset); cudaFree(d_result); return err; }
    
    cudaMemcpy(d_target, target_hash, 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_charset, charset, charset_len, cudaMemcpyHostToDevice);
    
    int init_found = 0;
    cudaMemcpy(d_found, &init_found, sizeof(int), cudaMemcpyHostToDevice);
    
    int threads_per_block = 256;
    int num_blocks = (count + threads_per_block - 1) / threads_per_block;
    
    md2_crack_kernel<<<num_blocks, threads_per_block>>>(
        d_target, start_index, count, d_charset, charset_len, key_length, d_result, d_found
    );
    
    err = cudaDeviceSynchronize();
    
    cudaMemcpy(found_flag, d_found, sizeof(int), cudaMemcpyDeviceToHost);
    if (*found_flag) {
        cudaMemcpy(result_key, d_result, 64, cudaMemcpyDeviceToHost);
    }
    
    cudaFree(d_target);
    cudaFree(d_charset);
    cudaFree(d_result);
    cudaFree(d_found);
    
    return err;
}

} // namespace hash
} // namespace cuda
} // namespace cryptopdc
