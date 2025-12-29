#ifndef CRYPTOPDC_CUDA_MD6_KERNEL_CUH
#define CRYPTOPDC_CUDA_MD6_KERNEL_CUH

#include <cstdint>
#include <cstddef>

namespace cryptopdc {
namespace cuda {
namespace hash {

// MD6-128 CUDA functions
__global__ void md6_128_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
);

void launch_md6_128_crack(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index,
    int blocks,
    int threads_per_block
);

// MD6-256 CUDA functions
__global__ void md6_256_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
);

void launch_md6_256_crack(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index,
    int blocks,
    int threads_per_block
);

// MD6-512 CUDA functions
__global__ void md6_512_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
);

void launch_md6_512_crack(
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

#endif // CRYPTOPDC_CUDA_MD6_KERNEL_CUH
