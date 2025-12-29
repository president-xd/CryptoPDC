#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/md2.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

// Helper function to convert byte vector to hex string
std::string to_hex(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class MD2Test : public ::testing::Test {
protected:
    MD2 md2;
};

// RFC 1319 Test Vectors
TEST_F(MD2Test, EmptyString) {
    auto hash = md2.hash("");
    EXPECT_EQ(to_hex(hash), "8350e5a3e24c153df2275c9f80692773");
}

TEST_F(MD2Test, SingleCharA) {
    auto hash = md2.hash("a");
    EXPECT_EQ(to_hex(hash), "32ec01ec4a6dac72c0ab96fb34c0b5d1");
}

TEST_F(MD2Test, ABC) {
    auto hash = md2.hash("abc");
    EXPECT_EQ(to_hex(hash), "da853b0d3f88d99b30283a69e6ded6bb");
}

TEST_F(MD2Test, MessageDigest) {
    auto hash = md2.hash("message digest");
    EXPECT_EQ(to_hex(hash), "ab4f496bfb2a530b219ff33031fe06b0");
}

TEST_F(MD2Test, Alphabet) {
    auto hash = md2.hash("abcdefghijklmnopqrstuvwxyz");
    EXPECT_EQ(to_hex(hash), "4e8ddff3650292ab5a4108c3aa47940b");
}

TEST_F(MD2Test, AlphanumericMixed) {
    auto hash = md2.hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    EXPECT_EQ(to_hex(hash), "da33def2a42df13975352846c30338cd");
}

TEST_F(MD2Test, NumericRepeat) {
    auto hash = md2.hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    EXPECT_EQ(to_hex(hash), "d5976f79d83d3a0dc9806c3c66f3efd8");
}

TEST_F(MD2Test, OutputSize) {
    EXPECT_EQ(md2.output_size(), 16);
}

TEST_F(MD2Test, Name) {
    EXPECT_EQ(md2.name(), "MD2");
}

TEST_F(MD2Test, Verify) {
    auto hash = md2.hash("test");
    EXPECT_TRUE(md2.verify("test", hash));
    EXPECT_FALSE(md2.verify("wrong", hash));
}
