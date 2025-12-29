#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <cstring>
#include "test_utils.cuh"
#include "cryptopdc/cuda/hash/md5_kernel.cuh"

using namespace cryptopdc::test::cuda;

class CudaMD5KernelTest : public CudaHashKernelTest {};

TEST_F(CudaMD5KernelTest, CrackKnownPasswordSimple) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
    uint8_t target_hash[] = {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
                            0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72};
    
    const char* charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int key_length = 3;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 26^3 = 17576
    cudaError_t err = cryptopdc::cuda::hash::launch_md5_crack(
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

TEST_F(CudaMD5KernelTest, CrackKnownPasswordNumeric) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // MD5("1234") = 81dc9bdb52d04dc20036dbd8313ed055
    uint8_t target_hash[] = {0x81, 0xdc, 0x9b, 0xdb, 0x52, 0xd0, 0x4d, 0xc2,
                            0x00, 0x36, 0xdb, 0xd8, 0x31, 0x3e, 0xd0, 0x55};
    
    const char* charset = "0123456789";
    int charset_len = 10;
    int key_length = 4;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 10^4 = 10000
    cudaError_t err = cryptopdc::cuda::hash::launch_md5_crack(
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

TEST_F(CudaMD5KernelTest, DoesNotFindNonExistentPassword) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // Random hash that doesn't match any 2-char password from 'ab' charset
    uint8_t target_hash[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
    const char* charset = "ab";
    int charset_len = 2;
    int key_length = 2;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 2^2 = 4
    cudaError_t err = cryptopdc::cuda::hash::launch_md5_crack(
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

TEST_F(CudaMD5KernelTest, PartialKeyspaceSearch) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // MD5("test") = 098f6bcd4621d373cade4e832627b4f6
    uint8_t target_hash[] = {0x09, 0x8f, 0x6b, 0xcd, 0x46, 0x21, 0xd3, 0x73,
                            0xca, 0xde, 0x4e, 0x83, 0x26, 0x27, 0xb4, 0xf6};
    
    const char* charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int key_length = 4;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Search larger keyspace - 26^4 = 456976
    cudaError_t err = cryptopdc::cuda::hash::launch_md5_crack(
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
