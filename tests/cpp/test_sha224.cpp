#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/sha224.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_sha224(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class SHA224Test : public ::testing::Test {
protected:
    SHA224 sha224;
};

// FIPS 180-4 Test Vectors
TEST_F(SHA224Test, EmptyString) {
    auto hash = sha224.hash("");
    EXPECT_EQ(to_hex_sha224(hash), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
}

TEST_F(SHA224Test, ABC) {
    auto hash = sha224.hash("abc");
    EXPECT_EQ(to_hex_sha224(hash), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
}

TEST_F(SHA224Test, TwoBlockMessage) {
    auto hash = sha224.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    EXPECT_EQ(to_hex_sha224(hash), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
}

TEST_F(SHA224Test, OutputSize) {
    EXPECT_EQ(sha224.output_size(), 28);
}

TEST_F(SHA224Test, Name) {
    EXPECT_EQ(sha224.name(), "SHA-224");
}

TEST_F(SHA224Test, Verify) {
    auto hash = sha224.hash("test");
    EXPECT_TRUE(sha224.verify("test", hash));
    EXPECT_FALSE(sha224.verify("wrong", hash));
}

TEST_F(SHA224Test, HashLength) {
    auto hash = sha224.hash("any string");
    EXPECT_EQ(hash.size(), 28);
}
