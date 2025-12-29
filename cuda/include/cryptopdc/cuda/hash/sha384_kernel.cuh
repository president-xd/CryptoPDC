#ifndef CRYPTOPDC_CUDA_SHA384_KERNEL_CUH
#define CRYPTOPDC_CUDA_SHA384_KERNEL_CUH

#include <cstdint>
#include <cstddef>

namespace cryptopdc {
namespace cuda {
namespace hash {

__global__ void sha384_crack_kernel(
    const uint8_t* target_hash,
    const char* wordlist,
    const size_t* word_offsets,
    size_t num_words,
    int* found,
    size_t* found_index
);

void launch_sha384_crack(
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

#endif // CRYPTOPDC_CUDA_SHA384_KERNEL_CUH
