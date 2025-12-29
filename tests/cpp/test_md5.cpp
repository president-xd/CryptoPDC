#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/md5.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_md5(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class MD5Test : public ::testing::Test {
protected:
    MD5 md5;
};

// RFC 1321 Test Vectors
TEST_F(MD5Test, EmptyString) {
    auto hash = md5.hash("");
    EXPECT_EQ(to_hex_md5(hash), "d41d8cd98f00b204e9800998ecf8427e");
}

TEST_F(MD5Test, SingleCharA) {
    auto hash = md5.hash("a");
    EXPECT_EQ(to_hex_md5(hash), "0cc175b9c0f1b6a831c399e269772661");
}

TEST_F(MD5Test, ABC) {
    auto hash = md5.hash("abc");
    EXPECT_EQ(to_hex_md5(hash), "900150983cd24fb0d6963f7d28e17f72");
}

TEST_F(MD5Test, MessageDigest) {
    auto hash = md5.hash("message digest");
    EXPECT_EQ(to_hex_md5(hash), "f96b697d7cb7938d525a2f31aaf161d0");
}

TEST_F(MD5Test, Alphabet) {
    auto hash = md5.hash("abcdefghijklmnopqrstuvwxyz");
    EXPECT_EQ(to_hex_md5(hash), "c3fcd3d76192e4007dfb496cca67e13b");
}

TEST_F(MD5Test, AlphanumericMixed) {
    auto hash = md5.hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    EXPECT_EQ(to_hex_md5(hash), "d174ab98d277d9f5a5611c2c9f419d9f");
}

TEST_F(MD5Test, NumericRepeat) {
    auto hash = md5.hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    EXPECT_EQ(to_hex_md5(hash), "57edf4a22be3c955ac49da2e2107b67a");
}

TEST_F(MD5Test, CommonPassword) {
    auto hash = md5.hash("password");
    EXPECT_EQ(to_hex_md5(hash), "5f4dcc3b5aa765d61d8327deb882cf99");
}

TEST_F(MD5Test, OutputSize) {
    EXPECT_EQ(md5.output_size(), 16);
}

TEST_F(MD5Test, Name) {
    EXPECT_EQ(md5.name(), "MD5");
}

TEST_F(MD5Test, Verify) {
    auto hash = md5.hash("test");
    EXPECT_TRUE(md5.verify("test", hash));
    EXPECT_FALSE(md5.verify("wrong", hash));
}
