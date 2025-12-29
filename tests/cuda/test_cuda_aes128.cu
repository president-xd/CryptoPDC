#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <cstring>
#include <vector>
#include <string>
#include "test_utils.cuh"
#include "cryptopdc/cuda/symmetric/aes128_kernel.cuh"

using namespace cryptopdc::test::cuda;

class CudaAES128KernelTest : public CudaSymmetricKernelTest {};

TEST_F(CudaAES128KernelTest, CudaAvailabilityCheck) {
    // Test that we can check CUDA availability
    bool available = cryptopdc::cuda::cuda_aes128_available();
    
    // This test should pass regardless of whether CUDA is available
    // It just checks that the function doesn't crash
    if (available) {
        SUCCEED() << "CUDA is available for AES-128 operations";
    } else {
        GTEST_SKIP() << "CUDA not available for AES-128 operations";
    }
}

TEST_F(CudaAES128KernelTest, BatchSizeCheck) {
    if (!cryptopdc::cuda::cuda_aes128_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // Get batch size
    size_t batch_size = cryptopdc::cuda::cuda_aes128_batch_size();
    
    // Batch size should be reasonable (at least 1)
    EXPECT_GE(batch_size, 1u) << "Batch size should be at least 1";
}

TEST_F(CudaAES128KernelTest, CrackKnownKeyFromDictionary) {
    if (!cryptopdc::cuda::cuda_aes128_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // NIST AES-128 test vector
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    // Ciphertext: 3ad77bb40d7a3660a89ecaf32466ef97
    
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint8_t ciphertext[16] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };
    
    // Create a dictionary with the correct key and some wrong keys
    std::vector<std::string> candidates = {
        "00000000000000000000000000000000",  // Wrong key
        "11111111111111111111111111111111",  // Wrong key
        "2b7e151628aed2a6abf7158809cf4f3c",  // Correct key
        "ffffffffffffffffffffffffffffffff"   // Wrong key
    };
    
    std::string result = cryptopdc::cuda::cuda_crack_aes128(
        plaintext, ciphertext, candidates
    );
    
    EXPECT_EQ(result, "2b7e151628aed2a6abf7158809cf4f3c");
}

TEST_F(CudaAES128KernelTest, DoesNotFindKeyNotInDictionary) {
    if (!cryptopdc::cuda::cuda_aes128_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint8_t ciphertext[16] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };
    
    // Dictionary without the correct key
    std::vector<std::string> candidates = {
        "00000000000000000000000000000000",
        "11111111111111111111111111111111",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ffffffffffffffffffffffffffffffff"
    };
    
    std::string result = cryptopdc::cuda::cuda_crack_aes128(
        plaintext, ciphertext, candidates
    );
    
    // Should return empty string when key not found
    EXPECT_TRUE(result.empty()) << "Should not find key that's not in dictionary";
}

TEST_F(CudaAES128KernelTest, EmptyDictionaryReturnsEmpty) {
    if (!cryptopdc::cuda::cuda_aes128_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16] = {0};
    
    std::vector<std::string> empty_candidates;
    
    std::string result = cryptopdc::cuda::cuda_crack_aes128(
        plaintext, ciphertext, empty_candidates
    );
    
    EXPECT_TRUE(result.empty()) << "Empty dictionary should return empty result";
}
