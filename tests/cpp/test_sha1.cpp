#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/sha1.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_sha1(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class SHA1Test : public ::testing::Test {
protected:
    SHA1 sha1;
};

// FIPS 180-4 Test Vectors
TEST_F(SHA1Test, EmptyString) {
    auto hash = sha1.hash("");
    EXPECT_EQ(to_hex_sha1(hash), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

TEST_F(SHA1Test, ABC) {
    auto hash = sha1.hash("abc");
    EXPECT_EQ(to_hex_sha1(hash), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

TEST_F(SHA1Test, TwoBlockMessage) {
    auto hash = sha1.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    EXPECT_EQ(to_hex_sha1(hash), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

TEST_F(SHA1Test, QuickBrownFox) {
    auto hash = sha1.hash("The quick brown fox jumps over the lazy dog");
    EXPECT_EQ(to_hex_sha1(hash), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
}

TEST_F(SHA1Test, QuickBrownFoxPeriod) {
    auto hash = sha1.hash("The quick brown fox jumps over the lazy cog");
    EXPECT_EQ(to_hex_sha1(hash), "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");
}

TEST_F(SHA1Test, OutputSize) {
    EXPECT_EQ(sha1.output_size(), 20);
}

TEST_F(SHA1Test, Name) {
    EXPECT_EQ(sha1.name(), "SHA-1");
}

TEST_F(SHA1Test, Verify) {
    auto hash = sha1.hash("test");
    EXPECT_TRUE(sha1.verify("test", hash));
    EXPECT_FALSE(sha1.verify("wrong", hash));
}
