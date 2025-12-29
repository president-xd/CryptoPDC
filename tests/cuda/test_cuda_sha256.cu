#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <cstring>
#include "test_utils.cuh"
#include "cryptopdc/cuda/hash/sha256_kernel.cuh"

using namespace cryptopdc::test::cuda;

class CudaSHA256KernelTest : public CudaHashKernelTest {};

TEST_F(CudaSHA256KernelTest, CrackKnownPasswordSimple) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    uint8_t target_hash[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    
    const char* charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int key_length = 3;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 26^3 = 17576
    cudaError_t err = cryptopdc::cuda::hash::launch_sha256_crack(
        target_hash,
        0,                    // start_index
        17576,               // count (entire keyspace)
        charset,
        charset_len,
        key_length,
        result_key,
        &found_flag,
        0                     // device_id
    );
    
    ASSERT_EQ(err, cudaSuccess);
    EXPECT_EQ(found_flag, 1);
    EXPECT_STREQ(result_key, "abc");
}

TEST_F(CudaSHA256KernelTest, CrackKnownPasswordNumeric) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // SHA256("1234") = 03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
    uint8_t target_hash[] = {
        0x03, 0xac, 0x67, 0x42, 0x16, 0xf3, 0xe1, 0x5c,
        0x76, 0x1e, 0xe1, 0xa5, 0xe2, 0x55, 0xf0, 0x67,
        0x95, 0x36, 0x23, 0xc8, 0xb3, 0x88, 0xb4, 0x45,
        0x9e, 0x13, 0xf9, 0x78, 0xd7, 0xc8, 0x46, 0xf4
    };
    
    const char* charset = "0123456789";
    int charset_len = 10;
    int key_length = 4;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 10^4 = 10000
    cudaError_t err = cryptopdc::cuda::hash::launch_sha256_crack(
        target_hash,
        0,
        10000,
        charset,
        charset_len,
        key_length,
        result_key,
        &found_flag,
        0
    );
    
    ASSERT_EQ(err, cudaSuccess);
    EXPECT_EQ(found_flag, 1);
    EXPECT_STREQ(result_key, "1234");
}

TEST_F(CudaSHA256KernelTest, DoesNotFindNonExistentPassword) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // Random hash that doesn't match any 2-char password from 'ab' charset
    uint8_t target_hash[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    
    const char* charset = "ab";
    int charset_len = 2;
    int key_length = 2;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 2^2 = 4
    cudaError_t err = cryptopdc::cuda::hash::launch_sha256_crack(
        target_hash,
        0,
        4,
        charset,
        charset_len,
        key_length,
        result_key,
        &found_flag,
        0
    );
    
    ASSERT_EQ(err, cudaSuccess);
    EXPECT_EQ(found_flag, 0);  // Should NOT find it
}

TEST_F(CudaSHA256KernelTest, PartialKeyspaceSearch) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    uint8_t target_hash[] = {
        0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
        0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
        0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
        0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08
    };
    
    const char* charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int key_length = 4;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Search larger keyspace - 26^4 = 456976
    cudaError_t err = cryptopdc::cuda::hash::launch_sha256_crack(
        target_hash,
        0,
        456976,
        charset,
        charset_len,
        key_length,
        result_key,
        &found_flag,
        0
    );
    
    ASSERT_EQ(err, cudaSuccess);
    EXPECT_EQ(found_flag, 1);
    EXPECT_STREQ(result_key, "test");
}
