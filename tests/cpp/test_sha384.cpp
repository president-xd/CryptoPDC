#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/sha384.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_sha384(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class SHA384Test : public ::testing::Test {
protected:
    SHA384 sha384;
};

// FIPS 180-4 Test Vectors
TEST_F(SHA384Test, EmptyString) {
    auto hash = sha384.hash("");
    EXPECT_EQ(to_hex_sha384(hash), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
}

TEST_F(SHA384Test, ABC) {
    auto hash = sha384.hash("abc");
    EXPECT_EQ(to_hex_sha384(hash), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
}

TEST_F(SHA384Test, TwoBlockMessage) {
    auto hash = sha384.hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    EXPECT_EQ(to_hex_sha384(hash), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
}

TEST_F(SHA384Test, OutputSize) {
    EXPECT_EQ(sha384.output_size(), 48);
}

TEST_F(SHA384Test, Name) {
    EXPECT_EQ(sha384.name(), "SHA-384");
}

TEST_F(SHA384Test, Verify) {
    auto hash = sha384.hash("test");
    EXPECT_TRUE(sha384.verify("test", hash));
    EXPECT_FALSE(sha384.verify("wrong", hash));
}

TEST_F(SHA384Test, HashLength) {
    auto hash = sha384.hash("any string");
    EXPECT_EQ(hash.size(), 48);
}
