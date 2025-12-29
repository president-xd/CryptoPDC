#include "cryptopdc/cuda/hash/md4_kernel.cuh"
#include "cryptopdc/cuda/common.cuh"
#include <cstring>

namespace cryptopdc {
namespace cuda {
namespace hash {

// Device MD4 functions
#define MD4_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))

#define MD4_ROUND1(a, b, c, d, x, s) \
    a = rotl((a + MD4_F(b, c, d) + x), s)

#define MD4_ROUND2(a, b, c, d, x, s) \
    a = rotl((a + MD4_G(b, c, d) + x + 0x5A827999), s)

#define MD4_ROUND3(a, b, c, d, x, s) \
    a = rotl((a + MD4_H(b, c, d) + x + 0x6ED9EBA1), s)

__device__ void md4_hash_device(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;
    
    uint8_t msg[128];
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    
    for (size_t i = 0; i < length; i++) {
        msg[i] = input[i];
    }
    msg[length] = 0x80;
    
    for (size_t i = length + 1; i < new_len; i++) {
        msg[i] = 0;
    }
    
    uint64_t bits_len = length * 8;
    memcpy(msg + new_len, &bits_len, 8);
    
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t* X = (uint32_t*)(msg + offset);
        
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        
        // Round 1
        MD4_ROUND1(a, b, c, d, X[0],  3);
        MD4_ROUND1(d, a, b, c, X[1],  7);
        MD4_ROUND1(c, d, a, b, X[2],  11);
        MD4_ROUND1(b, c, d, a, X[3],  19);
        MD4_ROUND1(a, b, c, d, X[4],  3);
        MD4_ROUND1(d, a, b, c, X[5],  7);
        MD4_ROUND1(c, d, a, b, X[6],  11);
        MD4_ROUND1(b, c, d, a, X[7],  19);
        MD4_ROUND1(a, b, c, d, X[8],  3);
        MD4_ROUND1(d, a, b, c, X[9],  7);
        MD4_ROUND1(c, d, a, b, X[10], 11);
        MD4_ROUND1(b, c, d, a, X[11], 19);
        MD4_ROUND1(a, b, c, d, X[12], 3);
        MD4_ROUND1(d, a, b, c, X[13], 7);
        MD4_ROUND1(c, d, a, b, X[14], 11);
        MD4_ROUND1(b, c, d, a, X[15], 19);
        
        // Round 2
        MD4_ROUND2(a, b, c, d, X[0],  3);
        MD4_ROUND2(d, a, b, c, X[4],  5);
        MD4_ROUND2(c, d, a, b, X[8],  9);
        MD4_ROUND2(b, c, d, a, X[12], 13);
        MD4_ROUND2(a, b, c, d, X[1],  3);
        MD4_ROUND2(d, a, b, c, X[5],  5);
        MD4_ROUND2(c, d, a, b, X[9],  9);
        MD4_ROUND2(b, c, d, a, X[13], 13);
        MD4_ROUND2(a, b, c, d, X[2],  3);
        MD4_ROUND2(d, a, b, c, X[6],  5);
        MD4_ROUND2(c, d, a, b, X[10], 9);
        MD4_ROUND2(b, c, d, a, X[14], 13);
        MD4_ROUND2(a, b, c, d, X[3],  3);
        MD4_ROUND2(d, a, b, c, X[7],  5);
        MD4_ROUND2(c, d, a, b, X[11], 9);
        MD4_ROUND2(b, c, d, a, X[15], 13);
        
        // Round 3
        MD4_ROUND3(a, b, c, d, X[0],  3);
        MD4_ROUND3(d, a, b, c, X[8],  9);
        MD4_ROUND3(c, d, a, b, X[4],  11);
        MD4_ROUND3(b, c, d, a, X[12], 15);
        MD4_ROUND3(a, b, c, d, X[2],  3);
        MD4_ROUND3(d, a, b, c, X[10], 9);
        MD4_ROUND3(c, d, a, b, X[6],  11);
        MD4_ROUND3(b, c, d, a, X[14], 15);
        MD4_ROUND3(a, b, c, d, X[1],  3);
        MD4_ROUND3(d, a, b, c, X[9],  9);
        MD4_ROUND3(c, d, a, b, X[5],  11);
        MD4_ROUND3(b, c, d, a, X[13], 15);
        MD4_ROUND3(a, b, c, d, X[3],  3);
        MD4_ROUND3(d, a, b, c, X[11], 9);
        MD4_ROUND3(c, d, a, b, X[7],  11);
        MD4_ROUND3(b, c, d, a, X[15], 15);
        
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }
    
    memcpy(output, &h0, 4);
    memcpy(output + 4, &h1, 4);
    memcpy(output + 8, &h2, 4);
    memcpy(output + 12, &h3, 4);
}

__global__ void md4_crack_kernel(
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
    md4_hash_device((const uint8_t*)key, key_length, computed_hash);
    
    if (memcmp_device(computed_hash, target_hash, 16)) {
        if (atomicCAS(found_flag, 0, 1) == 0) {
            for (int i = 0; i < key_length; i++) {
                result_key[i] = key[i];
            }
            result_key[key_length] = '\0';
        }
    }
}

cudaError_t launch_md4_crack(
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
    
    md4_crack_kernel<<<num_blocks, threads_per_block>>>(
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
