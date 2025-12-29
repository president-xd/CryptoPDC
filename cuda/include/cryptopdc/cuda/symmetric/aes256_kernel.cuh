#ifndef CRYPTOPDC_CUDA_AES256_KERNEL_CUH
#define CRYPTOPDC_CUDA_AES256_KERNEL_CUH

#include <cstdint>
#include <string>
#include <vector>

namespace cryptopdc {
namespace cuda {

/**
 * @brief CUDA-accelerated AES-256 key cracker
 * 
 * Performs parallel brute-force attack on AES-256 encryption
 * by testing multiple candidate keys against known plaintext/ciphertext pairs.
 */

/**
 * @brief Try to crack AES-256 key using dictionary attack
 * @param plaintext 16-byte known plaintext
 * @param ciphertext 16-byte known ciphertext  
 * @param candidates Vector of candidate keys to try (each 32 bytes)
 * @return Found key as hex string, or empty string if not found
 */
std::string cuda_crack_aes256(
    const uint8_t* plaintext,
    const uint8_t* ciphertext,
    const std::vector<std::string>& candidates
);

/**
 * @brief Check if CUDA is available for AES-256 operations
 * @return true if CUDA device is available
 */
bool cuda_aes256_available();

/**
 * @brief Get the optimal batch size for AES-256 cracking
 * @return Recommended number of candidates per batch
 */
size_t cuda_aes256_batch_size();

} // namespace cuda
} // namespace cryptopdc

#endif // CRYPTOPDC_CUDA_AES256_KERNEL_CUH
