#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <cstring>
#include "test_utils.cuh"
#include "cryptopdc/cuda/hash/sha512_kernel.cuh"

using namespace cryptopdc::test::cuda;

class CudaSHA512KernelTest : public CudaHashKernelTest {};

TEST_F(CudaSHA512KernelTest, CrackKnownPasswordSimple) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // SHA512("abc") = ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
    //                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
    uint8_t target_hash[] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };
    
    const char* charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int key_length = 3;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 26^3 = 17576
    cudaError_t err = cryptopdc::cuda::hash::launch_sha512_crack(
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

TEST_F(CudaSHA512KernelTest, CrackKnownPasswordNumeric) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // SHA512("1234") = d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176
    //                 b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db
    uint8_t target_hash[] = {
        0xd4, 0x04, 0x55, 0x9f, 0x60, 0x2e, 0xab, 0x6f,
        0xd6, 0x02, 0xac, 0x76, 0x80, 0xda, 0xcb, 0xfa,
        0xad, 0xd1, 0x36, 0x30, 0x33, 0x5e, 0x95, 0x1f,
        0x09, 0x7a, 0xf3, 0x90, 0x0e, 0x9d, 0xe1, 0x76,
        0xb6, 0xdb, 0x28, 0x51, 0x2f, 0x2e, 0x00, 0x0b,
        0x9d, 0x04, 0xfb, 0xa5, 0x13, 0x3e, 0x8b, 0x1c,
        0x6e, 0x8d, 0xf5, 0x9d, 0xb3, 0xa8, 0xab, 0x9d,
        0x60, 0xbe, 0x4b, 0x97, 0xcc, 0x9e, 0x81, 0xdb
    };
    
    const char* charset = "0123456789";
    int charset_len = 10;
    int key_length = 4;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Try to crack - keyspace is 10^4 = 10000
    cudaError_t err = cryptopdc::cuda::hash::launch_sha512_crack(
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

TEST_F(CudaSHA512KernelTest, DoesNotFindNonExistentPassword) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // Random hash that doesn't match any 2-char password from 'ab' charset
    uint8_t target_hash[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
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
    cudaError_t err = cryptopdc::cuda::hash::launch_sha512_crack(
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

TEST_F(CudaSHA512KernelTest, PartialKeyspaceSearch) {
    if (!cuda_available()) {
        GTEST_SKIP() << "CUDA not available";
    }
    
    // SHA512("test") = ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff
    uint8_t target_hash[] = {
        0xee, 0x26, 0xb0, 0xdd, 0x4a, 0xf7, 0xe7, 0x49,
        0xaa, 0x1a, 0x8e, 0xe3, 0xc1, 0x0a, 0xe9, 0x92,
        0x3f, 0x61, 0x89, 0x80, 0x77, 0x2e, 0x47, 0x3f,
        0x88, 0x19, 0xa5, 0xd4, 0x94, 0x0e, 0x0d, 0xb2,
        0x7a, 0xc1, 0x85, 0xf8, 0xa0, 0xe1, 0xd5, 0xf8,
        0x4f, 0x88, 0xbc, 0x88, 0x7f, 0xd6, 0x7b, 0x14,
        0x37, 0x32, 0xc3, 0x04, 0xcc, 0x5f, 0xa9, 0xad,
        0x8e, 0x6f, 0x57, 0xf5, 0x00, 0x28, 0xa8, 0xff
    };
    
    const char* charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int key_length = 4;
    
    char result_key[64] = {0};
    int found_flag = 0;
    
    // Search larger keyspace - 26^4 = 456976
    cudaError_t err = cryptopdc::cuda::hash::launch_sha512_crack(
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
