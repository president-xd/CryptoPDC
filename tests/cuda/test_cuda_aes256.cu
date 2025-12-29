#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <cstring>
#include <vector>
#include <string>
#include "test_utils.cuh"
#include "cryptopdc/cuda/symmetric/aes256_kernel.cuh"

using namespace cryptopdc::test::cuda;

class CudaAES256KernelTest : public CudaSymmetricKernelTest {};

TEST_F(CudaAES256KernelTest, CudaAvailabilityCheck) {
    bool available = cryptopdc::cuda::cuda_aes256_available();
    
    if (available) {
        SUCCEED() << "CUDA is available for AES-256 operations";
    } else {
        GTEST_SKIP() << "CUDA not available for AES-256 operations";
    }
}

TEST_F(CudaAES256KernelTest, BatchSizeCheck) {
    if (!cryptopdc::cuda::cuda_aes256_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    size_t batch_size = cryptopdc::cuda::cuda_aes256_batch_size();
    EXPECT_GE(batch_size, 1u) << "Batch size should be at least 1";
}

TEST_F(CudaAES256KernelTest, CrackKnownKeyFromDictionary) {
    if (!cryptopdc::cuda::cuda_aes256_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // NIST AES-256 test vector
    // Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    // Plaintext: 6bc1bee22e409f96e93d7e117393172a
    // Ciphertext: f3eed1bdb5d2a03c064b5a7e3db181f8
    
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint8_t ciphertext[16] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
    };
    
    // Create dictionary with correct key and wrong keys (32-byte keys = 64 hex chars)
    std::vector<std::string> candidates = {
        "0000000000000000000000000000000000000000000000000000000000000000",  // Wrong key
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",  // Correct key
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"   // Wrong key
    };
    
    std::string result = cryptopdc::cuda::cuda_crack_aes256(
        plaintext, ciphertext, candidates
    );
    
    EXPECT_EQ(result, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
}

TEST_F(CudaAES256KernelTest, DoesNotFindKeyNotInDictionary) {
    if (!cryptopdc::cuda::cuda_aes256_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint8_t ciphertext[16] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
    };
    
    // Dictionary without correct key
    std::vector<std::string> candidates = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "1111111111111111111111111111111111111111111111111111111111111111"
    };
    
    std::string result = cryptopdc::cuda::cuda_crack_aes256(
        plaintext, ciphertext, candidates
    );
    
    EXPECT_TRUE(result.empty()) << "Should not find key that's not in dictionary";
}

TEST_F(CudaAES256KernelTest, EmptyDictionaryReturnsEmpty) {
    if (!cryptopdc::cuda::cuda_aes256_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16] = {0};
    
    std::vector<std::string> empty_candidates;
    
    std::string result = cryptopdc::cuda::cuda_crack_aes256(
        plaintext, ciphertext, empty_candidates
    );
    
    EXPECT_TRUE(result.empty()) << "Empty dictionary should return empty result";
}
