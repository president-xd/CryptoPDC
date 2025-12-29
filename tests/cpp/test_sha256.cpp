#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/sha256.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_sha256(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class SHA256Test : public ::testing::Test {
protected:
    SHA256 sha256;
};

// FIPS 180-4 Test Vectors
TEST_F(SHA256Test, EmptyString) {
    auto hash = sha256.hash("");
    EXPECT_EQ(to_hex_sha256(hash), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(SHA256Test, ABC) {
    auto hash = sha256.hash("abc");
    EXPECT_EQ(to_hex_sha256(hash), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(SHA256Test, TwoBlockMessage) {
    auto hash = sha256.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    EXPECT_EQ(to_hex_sha256(hash), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_F(SHA256Test, QuickBrownFox) {
    auto hash = sha256.hash("The quick brown fox jumps over the lazy dog");
    EXPECT_EQ(to_hex_sha256(hash), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
}

TEST_F(SHA256Test, OutputSize) {
    EXPECT_EQ(sha256.output_size(), 32);
}

TEST_F(SHA256Test, Name) {
    EXPECT_EQ(sha256.name(), "SHA-256");
}

TEST_F(SHA256Test, Verify) {
    auto hash = sha256.hash("test");
    EXPECT_TRUE(sha256.verify("test", hash));
    EXPECT_FALSE(sha256.verify("wrong", hash));
}
