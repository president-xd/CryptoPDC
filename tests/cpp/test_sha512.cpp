#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/sha512.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_sha512(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class SHA512Test : public ::testing::Test {
protected:
    SHA512 sha512;
};

// FIPS 180-4 Test Vectors
TEST_F(SHA512Test, EmptyString) {
    auto hash = sha512.hash("");
    EXPECT_EQ(to_hex_sha512(hash), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

TEST_F(SHA512Test, ABC) {
    auto hash = sha512.hash("abc");
    EXPECT_EQ(to_hex_sha512(hash), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

TEST_F(SHA512Test, TwoBlockMessage) {
    auto hash = sha512.hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    EXPECT_EQ(to_hex_sha512(hash), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

TEST_F(SHA512Test, QuickBrownFox) {
    auto hash = sha512.hash("The quick brown fox jumps over the lazy dog");
    EXPECT_EQ(to_hex_sha512(hash), "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
}

TEST_F(SHA512Test, OutputSize) {
    EXPECT_EQ(sha512.output_size(), 64);
}

TEST_F(SHA512Test, Name) {
    EXPECT_EQ(sha512.name(), "SHA-512");
}

TEST_F(SHA512Test, Verify) {
    auto hash = sha512.hash("test");
    EXPECT_TRUE(sha512.verify("test", hash));
    EXPECT_FALSE(sha512.verify("wrong", hash));
}
