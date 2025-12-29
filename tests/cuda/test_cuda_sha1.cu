#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <cstring>
#include "test_utils.cuh"
#include "cryptopdc/cuda/hash/sha1_kernel.cuh"

using namespace cryptopdc::test::cuda;

class CudaSHA1KernelTest : public CudaHashKernelTest {};

TEST_F(CudaSHA1KernelTest, CrackKnownPasswordSimple) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
    uint8_t target_hash[] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
                            0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
                            0x9c, 0xd0, 0xd8, 0x9d};
    
    const char* charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int key_length = 3;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 26^3 = 17576
    cudaError_t err = cryptopdc::cuda::hash::launch_sha1_crack(
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

TEST_F(CudaSHA1KernelTest, CrackKnownPasswordNumeric) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // SHA1("1234") = 7110eda4d09e062aa5e4a390b0a572ac0d2c0220
    uint8_t target_hash[] = {0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x06, 0x2a,
                            0xa5, 0xe4, 0xa3, 0x90, 0xb0, 0xa5, 0x72, 0xac,
                            0x0d, 0x2c, 0x02, 0x20};
    
    const char* charset = "0123456789";
    int charset_len = 10;
    int key_length = 4;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 10^4 = 10000
    cudaError_t err = cryptopdc::cuda::hash::launch_sha1_crack(
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

TEST_F(CudaSHA1KernelTest, DoesNotFindNonExistentPassword) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // Random hash that doesn't match any 2-char password from 'ab' charset
    uint8_t target_hash[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff};
    
    const char* charset = "ab";
    int charset_len = 2;
    int key_length = 2;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 2^2 = 4
    cudaError_t err = cryptopdc::cuda::hash::launch_sha1_crack(
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

TEST_F(CudaSHA1KernelTest, PartialKeyspaceSearch) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // SHA1("test") = a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
    uint8_t target_hash[] = {0xa9, 0x4a, 0x8f, 0xe5, 0xcc, 0xb1, 0x9b, 0xa6,
                            0x1c, 0x4c, 0x08, 0x73, 0xd3, 0x91, 0xe9, 0x87,
                            0x98, 0x2f, 0xbb, 0xd3};
    
    const char* charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int key_length = 4;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Search larger keyspace - 26^4 = 456976
    cudaError_t err = cryptopdc::cuda::hash::launch_sha1_crack(
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
