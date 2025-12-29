#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/ripemd.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_ripemd(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

// RIPEMD-128 Tests
class RIPEMD128Test : public ::testing::Test {
protected:
    RIPEMD128 ripemd;
};

TEST_F(RIPEMD128Test, EmptyString) {
    auto hash = ripemd.hash("");
    EXPECT_EQ(to_hex_ripemd(hash), "cdf26213a150dc3ecb610f18f6b38b46");
}

TEST_F(RIPEMD128Test, SingleCharA) {
    auto hash = ripemd.hash("a");
    EXPECT_EQ(to_hex_ripemd(hash), "86be7afa339d0fc7cfc785e72f578d33");
}

TEST_F(RIPEMD128Test, ABC) {
    auto hash = ripemd.hash("abc");
    EXPECT_EQ(to_hex_ripemd(hash), "c14a12199c66e4ba84636b0f69144c77");
}

TEST_F(RIPEMD128Test, MessageDigest) {
    auto hash = ripemd.hash("message digest");
    EXPECT_EQ(to_hex_ripemd(hash), "9e327b3d6e523062afc1132d7df9d1b8");
}

TEST_F(RIPEMD128Test, Alphabet) {
    auto hash = ripemd.hash("abcdefghijklmnopqrstuvwxyz");
    EXPECT_EQ(to_hex_ripemd(hash), "fd2aa607f71dc8f510714922b371834e");
}

TEST_F(RIPEMD128Test, OutputSize) {
    EXPECT_EQ(ripemd.output_size(), 16);
}

TEST_F(RIPEMD128Test, Name) {
    EXPECT_EQ(ripemd.name(), "RIPEMD-128");
}

// RIPEMD-160 Tests
class RIPEMD160Test : public ::testing::Test {
protected:
    RIPEMD160 ripemd;
};

TEST_F(RIPEMD160Test, EmptyString) {
    auto hash = ripemd.hash("");
    EXPECT_EQ(to_hex_ripemd(hash), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
}

TEST_F(RIPEMD160Test, SingleCharA) {
    auto hash = ripemd.hash("a");
    EXPECT_EQ(to_hex_ripemd(hash), "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
}

TEST_F(RIPEMD160Test, ABC) {
    auto hash = ripemd.hash("abc");
    EXPECT_EQ(to_hex_ripemd(hash), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
}

TEST_F(RIPEMD160Test, MessageDigest) {
    auto hash = ripemd.hash("message digest");
    EXPECT_EQ(to_hex_ripemd(hash), "5d0689ef49d2fae572b881b123a85ffa21595f36");
}

TEST_F(RIPEMD160Test, Alphabet) {
    auto hash = ripemd.hash("abcdefghijklmnopqrstuvwxyz");
    EXPECT_EQ(to_hex_ripemd(hash), "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
}

TEST_F(RIPEMD160Test, OutputSize) {
    EXPECT_EQ(ripemd.output_size(), 20);
}

TEST_F(RIPEMD160Test, Name) {
    EXPECT_EQ(ripemd.name(), "RIPEMD-160");
}

TEST_F(RIPEMD160Test, Verify) {
    auto hash = ripemd.hash("test");
    EXPECT_TRUE(ripemd.verify("test", hash));
    EXPECT_FALSE(ripemd.verify("wrong", hash));
}

// RIPEMD-256 Tests
class RIPEMD256Test : public ::testing::Test {
protected:
    RIPEMD256 ripemd;
};

TEST_F(RIPEMD256Test, EmptyString) {
    auto hash = ripemd.hash("");
    EXPECT_EQ(to_hex_ripemd(hash), "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d");
}

TEST_F(RIPEMD256Test, SingleCharA) {
    auto hash = ripemd.hash("a");
    EXPECT_EQ(to_hex_ripemd(hash), "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925");
}

TEST_F(RIPEMD256Test, ABC) {
    auto hash = ripemd.hash("abc");
    EXPECT_EQ(to_hex_ripemd(hash), "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65");
}

TEST_F(RIPEMD256Test, OutputSize) {
    EXPECT_EQ(ripemd.output_size(), 32);
}

TEST_F(RIPEMD256Test, Name) {
    EXPECT_EQ(ripemd.name(), "RIPEMD-256");
}

// RIPEMD-320 Tests
class RIPEMD320Test : public ::testing::Test {
protected:
    RIPEMD320 ripemd;
};

TEST_F(RIPEMD320Test, EmptyString) {
    auto hash = ripemd.hash("");
    EXPECT_EQ(to_hex_ripemd(hash), "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8");
}

TEST_F(RIPEMD320Test, SingleCharA) {
    auto hash = ripemd.hash("a");
    EXPECT_EQ(to_hex_ripemd(hash), "ce78850638f92f9ea1e6e75d0fb0c3e2d4c6c9b3f0e4c7b7b8f5d5a3e4c6d9b2e8f4d5c9a7e3f7c9");
}

TEST_F(RIPEMD320Test, OutputSize) {
    EXPECT_EQ(ripemd.output_size(), 40);
}

TEST_F(RIPEMD320Test, Name) {
    EXPECT_EQ(ripemd.name(), "RIPEMD-320");
}

TEST_F(RIPEMD320Test, HashLength) {
    auto hash = ripemd.hash("test");
    EXPECT_EQ(hash.size(), 40);
}

TEST_F(RIPEMD320Test, Consistency) {
    auto hash1 = ripemd.hash("hello");
    auto hash2 = ripemd.hash("hello");
    EXPECT_EQ(hash1, hash2);
}
