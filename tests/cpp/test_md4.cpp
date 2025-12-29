#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/md4.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_md4(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class MD4Test : public ::testing::Test {
protected:
    MD4 md4;
};

// RFC 1320 Test Vectors
TEST_F(MD4Test, EmptyString) {
    auto hash = md4.hash("");
    EXPECT_EQ(to_hex_md4(hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
}

TEST_F(MD4Test, SingleCharA) {
    auto hash = md4.hash("a");
    EXPECT_EQ(to_hex_md4(hash), "bde52cb31de33e46245e05fbdbd6fb24");
}

TEST_F(MD4Test, ABC) {
    auto hash = md4.hash("abc");
    EXPECT_EQ(to_hex_md4(hash), "a448017aaf21d8525fc10ae87aa6729d");
}

TEST_F(MD4Test, MessageDigest) {
    auto hash = md4.hash("message digest");
    EXPECT_EQ(to_hex_md4(hash), "d9130a8164549fe818874806e1c7014b");
}

TEST_F(MD4Test, Alphabet) {
    auto hash = md4.hash("abcdefghijklmnopqrstuvwxyz");
    EXPECT_EQ(to_hex_md4(hash), "d79e1c308aa5bbcdeea8ed63df412da9");
}

TEST_F(MD4Test, AlphanumericMixed) {
    auto hash = md4.hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    EXPECT_EQ(to_hex_md4(hash), "043f8582f241db351ce627e153e7f0e4");
}

TEST_F(MD4Test, NumericRepeat) {
    auto hash = md4.hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    EXPECT_EQ(to_hex_md4(hash), "e33b4ddc9c38f2199c3e7b164fcc0536");
}

TEST_F(MD4Test, OutputSize) {
    EXPECT_EQ(md4.output_size(), 16);
}

TEST_F(MD4Test, Name) {
    EXPECT_EQ(md4.name(), "MD4");
}

TEST_F(MD4Test, Verify) {
    auto hash = md4.hash("test");
    EXPECT_TRUE(md4.verify("test", hash));
    EXPECT_FALSE(md4.verify("wrong", hash));
}
