#include "cryptopdc/cuda/symmetric/aes256_kernel.cuh"
#include "cryptopdc/cuda/common.cuh"
#include <cuda_runtime.h>
#include <cstring>
#include <algorithm>

namespace cryptopdc {
namespace cuda {

// AES S-box for AES-256
__constant__ uint8_t d_sbox256[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

__constant__ uint8_t d_rcon256[8] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
};

__device__ __forceinline__ uint8_t gf_mul2_256(uint8_t a) {
    return (a << 1) ^ ((a & 0x80) ? 0x1b : 0x00);
}

__device__ __forceinline__ uint8_t gf_mul3_256(uint8_t a) {
    return gf_mul2_256(a) ^ a;
}

// AES-256 key expansion (15 round keys, 240 bytes total)
__device__ void aes256_key_expansion(const uint8_t* key, uint8_t* round_keys) {
    // Copy original 32-byte key
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        round_keys[i] = key[i];
    }
    
    int bytes_generated = 32;
    int rcon_idx = 0;
    uint8_t temp[4];
    
    while (bytes_generated < 240) {
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            temp[i] = round_keys[bytes_generated - 4 + i];
        }
        
        if (bytes_generated % 32 == 0) {
            // RotWord + SubWord
            uint8_t t = temp[0];
            temp[0] = d_sbox256[temp[1]];
            temp[1] = d_sbox256[temp[2]];
            temp[2] = d_sbox256[temp[3]];
            temp[3] = d_sbox256[t];
            
            temp[0] ^= d_rcon256[rcon_idx++];
        } else if (bytes_generated % 32 == 16) {
            // Additional SubWord for AES-256 at position 16
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                temp[i] = d_sbox256[temp[i]];
            }
        }
        
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            round_keys[bytes_generated + i] = round_keys[bytes_generated - 32 + i] ^ temp[i];
        }
        bytes_generated += 4;
    }
}

__device__ void aes256_sub_bytes(uint8_t* state) {
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        state[i] = d_sbox256[state[i]];
    }
}

__device__ void aes256_shift_rows(uint8_t* state) {
    uint8_t temp;
    // Row 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    // Row 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    // Row 3
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

__device__ void aes256_mix_columns(uint8_t* state) {
    #pragma unroll
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        state[i]   = gf_mul2_256(a0) ^ gf_mul3_256(a1) ^ a2 ^ a3;
        state[i+1] = a0 ^ gf_mul2_256(a1) ^ gf_mul3_256(a2) ^ a3;
        state[i+2] = a0 ^ a1 ^ gf_mul2_256(a2) ^ gf_mul3_256(a3);
        state[i+3] = gf_mul3_256(a0) ^ a1 ^ a2 ^ gf_mul2_256(a3);
    }
}

__device__ void aes256_add_round_key(uint8_t* state, const uint8_t* round_key) {
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

// AES-256 encrypt single block (14 rounds)
__device__ void aes256_encrypt_block(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext) {
    uint8_t state[16];
    uint8_t round_keys[240];  // 15 * 16 = 240 bytes for AES-256
    
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        state[i] = plaintext[i];
    }
    
    aes256_key_expansion(key, round_keys);
    
    // Initial round
    aes256_add_round_key(state, round_keys);
    
    // Main rounds 1-13
    #pragma unroll
    for (int round = 1; round < 14; round++) {
        aes256_sub_bytes(state);
        aes256_shift_rows(state);
        aes256_mix_columns(state);
        aes256_add_round_key(state, round_keys + round * 16);
    }
    
    // Final round (no MixColumns)
    aes256_sub_bytes(state);
    aes256_shift_rows(state);
    aes256_add_round_key(state, round_keys + 224);
    
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        ciphertext[i] = state[i];
    }
}

// Kernel to crack AES-256 keys
__global__ void aes256_crack_kernel(
    const uint8_t* __restrict__ plaintext,
    const uint8_t* __restrict__ expected_ciphertext,
    const uint8_t* __restrict__ candidate_keys,
    uint32_t num_candidates,
    int* __restrict__ found_idx
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (idx >= num_candidates || *found_idx >= 0) return;
    
    const uint8_t* key = candidate_keys + idx * 32;  // 32 bytes per key
    uint8_t computed_ciphertext[16];
    
    aes256_encrypt_block(plaintext, key, computed_ciphertext);
    
    bool match = true;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (computed_ciphertext[i] != expected_ciphertext[i]) {
            match = false;
            break;
        }
    }
    
    if (match) {
        atomicCAS(found_idx, -1, idx);
    }
}

static void hex_to_bytes256(const std::string& hex, uint8_t* bytes, size_t max_len) {
    size_t len = std::min(hex.length() / 2, max_len);
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex.c_str() + 2 * i, "%02x", &byte);
        bytes[i] = static_cast<uint8_t>(byte);
    }
    for (size_t i = len; i < max_len; i++) {
        bytes[i] = 0;
    }
}

std::string cuda_crack_aes256(
    const uint8_t* plaintext,
    const uint8_t* ciphertext,
    const std::vector<std::string>& candidates
) {
    if (candidates.empty()) return "";
    
    cudaError_t err;
    
    uint8_t* d_plaintext;
    uint8_t* d_ciphertext;
    uint8_t* d_keys;
    int* d_found_idx;
    
    err = cudaMalloc(&d_plaintext, 16);
    if (err != cudaSuccess) return "";
    
    err = cudaMalloc(&d_ciphertext, 16);
    if (err != cudaSuccess) {
        cudaFree(d_plaintext);
        return "";
    }
    
    err = cudaMalloc(&d_found_idx, sizeof(int));
    if (err != cudaSuccess) {
        cudaFree(d_plaintext);
        cudaFree(d_ciphertext);
        return "";
    }
    
    cudaMemcpy(d_plaintext, plaintext, 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_ciphertext, ciphertext, 16, cudaMemcpyHostToDevice);
    
    int init_idx = -1;
    cudaMemcpy(d_found_idx, &init_idx, sizeof(int), cudaMemcpyHostToDevice);
    
    const size_t BATCH_SIZE = 1024 * 64;  // 64K keys per batch (largest keys = smallest batch)
    std::string result;
    
    for (size_t batch_start = 0; batch_start < candidates.size() && result.empty(); batch_start += BATCH_SIZE) {
        size_t batch_end = std::min(batch_start + BATCH_SIZE, candidates.size());
        size_t batch_count = batch_end - batch_start;
        
        std::vector<uint8_t> h_keys(batch_count * 32);
        for (size_t i = 0; i < batch_count; i++) {
            hex_to_bytes256(candidates[batch_start + i], h_keys.data() + i * 32, 32);
        }
        
        err = cudaMalloc(&d_keys, batch_count * 32);
        if (err != cudaSuccess) break;
        
        cudaMemcpy(d_keys, h_keys.data(), batch_count * 32, cudaMemcpyHostToDevice);
        cudaMemcpy(d_found_idx, &init_idx, sizeof(int), cudaMemcpyHostToDevice);
        
        int threads_per_block = 256;
        int num_blocks = std::min((int)((batch_count + threads_per_block - 1) / threads_per_block), 65535);
        
        for (size_t chunk_start = 0; chunk_start < batch_count; chunk_start += (size_t)num_blocks * threads_per_block) {
            size_t chunk_size = std::min(batch_count - chunk_start, (size_t)num_blocks * threads_per_block);
            int chunk_blocks = (chunk_size + threads_per_block - 1) / threads_per_block;
            
            aes256_crack_kernel<<<chunk_blocks, threads_per_block>>>(
                d_plaintext,
                d_ciphertext,
                d_keys + chunk_start * 32,
                chunk_size,
                d_found_idx
            );
            
            cudaDeviceSynchronize();
            
            int found_idx;
            cudaMemcpy(&found_idx, d_found_idx, sizeof(int), cudaMemcpyDeviceToHost);
            
            if (found_idx >= 0) {
                result = candidates[batch_start + chunk_start + found_idx];
                break;
            }
        }
        
        cudaFree(d_keys);
    }
    
    cudaFree(d_plaintext);
    cudaFree(d_ciphertext);
    cudaFree(d_found_idx);
    
    return result;
}

bool cuda_aes256_available() {
    int device_count = 0;
    cudaError_t err = cudaGetDeviceCount(&device_count);
    return (err == cudaSuccess && device_count > 0);
}

size_t cuda_aes256_batch_size() {
    return 1024 * 64;
}

} // namespace cuda
} // namespace cryptopdc
