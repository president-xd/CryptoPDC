#ifndef CRYPTOPDC_CUDA_RIPEMD_KERNEL_CUH
#define CRYPTOPDC_CUDA_RIPEMD_KERNEL_CUH

#include <cstdint>
#include <cstddef>

namespace cryptopdc {
namespace cuda {
namespace hash {

// RIPEMD-128 CUDA functions
__global__ void ripemd128_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
);

void launch_ripemd128_crack(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index,
    int blocks,
    int threads_per_block
);

// RIPEMD-160 CUDA functions
__global__ void ripemd160_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
);

void launch_ripemd160_crack(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index,
    int blocks,
    int threads_per_block
);

// RIPEMD-256 CUDA functions
__global__ void ripemd256_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
);

void launch_ripemd256_crack(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index,
    int blocks,
    int threads_per_block
);

// RIPEMD-320 CUDA functions
__global__ void ripemd320_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
);

void launch_ripemd320_crack(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index,
    int blocks,
    int threads_per_block
);

} // namespace hash
} // namespace cuda
} // namespace cryptopdc

#endif // CRYPTOPDC_CUDA_RIPEMD_KERNEL_CUH
