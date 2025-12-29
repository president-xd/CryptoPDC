#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/ntlm.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_ntlm(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class NTLMTest : public ::testing::Test {
protected:
    NTLM ntlm;
};

// NTLM Test Vectors (known values)
TEST_F(NTLMTest, EmptyPassword) {
    auto hash = ntlm.hash("");
    EXPECT_EQ(to_hex_ntlm(hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
}

TEST_F(NTLMTest, Password123) {
    auto hash = ntlm.hash("password");
    EXPECT_EQ(to_hex_ntlm(hash), "a4f49c406510bdcab6824ee7c30fd852");
}

TEST_F(NTLMTest, Test) {
    auto hash = ntlm.hash("test");
    EXPECT_EQ(to_hex_ntlm(hash), "0cb6948805f797bf2a82807973b89537");
}

TEST_F(NTLMTest, Admin) {
    auto hash = ntlm.hash("admin");
    EXPECT_EQ(to_hex_ntlm(hash), "209c6174da490caeb422f3fa5a7ae634");
}

TEST_F(NTLMTest, OutputSize) {
    EXPECT_EQ(ntlm.output_size(), 16);
}

TEST_F(NTLMTest, Name) {
    EXPECT_EQ(ntlm.name(), "NTLM");
}

TEST_F(NTLMTest, Verify) {
    auto hash = ntlm.hash("test");
    EXPECT_TRUE(ntlm.verify("test", hash));
    EXPECT_FALSE(ntlm.verify("wrong", hash));
}

TEST_F(NTLMTest, CaseSensitive) {
    auto hash1 = ntlm.hash("Password");
    auto hash2 = ntlm.hash("password");
    EXPECT_NE(hash1, hash2);
}

TEST_F(NTLMTest, UnicodeSupport) {
    // NTLM uses UTF-16LE encoding
    auto hash = ntlm.hash("hello");
    EXPECT_EQ(hash.size(), 16);
}
