#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <cstring>
#include <vector>
#include <string>
#include "test_utils.cuh"
#include "cryptopdc/cuda/symmetric/aes192_kernel.cuh"

using namespace cryptopdc::test::cuda;

class CudaAES192KernelTest : public CudaSymmetricKernelTest {};

TEST_F(CudaAES192KernelTest, CudaAvailabilityCheck) {
    // Test that we can check CUDA availability
    bool available = cryptopdc::cuda::cuda_aes192_available();
    
    if (available) {
        SUCCEED() << "CUDA is available for AES-192 operations";
    } else {
        GTEST_SKIP() << "CUDA not available for AES-192 operations";
    }
}

TEST_F(CudaAES192KernelTest, BatchSizeCheck) {
    if (!cryptopdc::cuda::cuda_aes192_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    size_t batch_size = cryptopdc::cuda::cuda_aes192_batch_size();
    EXPECT_GE(batch_size, 1u) << "Batch size should be at least 1";
}

TEST_F(CudaAES192KernelTest, CrackKnownKeyFromDictionary) {
    if (!cryptopdc::cuda::cuda_aes192_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // NIST AES-192 test vector
    // Key: 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    // Ciphertext: bd334f1d6e45f25ff712a214571fa5cc
    
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint8_t ciphertext[16] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc
    };
    
    // Create dictionary with correct key and wrong keys (24-byte keys = 48 hex chars)
    std::vector<std::string> candidates = {
        "000000000000000000000000000000000000000000000000",  // Wrong key
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",  // Correct key
        "ffffffffffffffffffffffffffffffffffffffffffff"       // Wrong key
    };
    
    std::string result = cryptopdc::cuda::cuda_crack_aes192(
        plaintext, ciphertext, candidates
    );
    
    EXPECT_EQ(result, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
}

TEST_F(CudaAES192KernelTest, DoesNotFindKeyNotInDictionary) {
    if (!cryptopdc::cuda::cuda_aes192_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint8_t ciphertext[16] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc
    };
    
    // Dictionary without correct key
    std::vector<std::string> candidates = {
        "000000000000000000000000000000000000000000000000",
        "111111111111111111111111111111111111111111111111"
    };
    
    std::string result = cryptopdc::cuda::cuda_crack_aes192(
        plaintext, ciphertext, candidates
    );
    
    EXPECT_TRUE(result.empty()) << "Should not find key that's not in dictionary";
}

TEST_F(CudaAES192KernelTest, EmptyDictionaryReturnsEmpty) {
    if (!cryptopdc::cuda::cuda_aes192_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16] = {0};
    
    std::vector<std::string> empty_candidates;
    
    std::string result = cryptopdc::cuda::cuda_crack_aes192(
        plaintext, ciphertext, empty_candidates
    );
    
    EXPECT_TRUE(result.empty()) << "Empty dictionary should return empty result";
}
