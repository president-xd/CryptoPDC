#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/md6.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_md6(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class MD6_128Test : public ::testing::Test {
protected:
    MD6_128 md6;
};

class MD6_256Test : public ::testing::Test {
protected:
    MD6_256 md6;
};

class MD6_512Test : public ::testing::Test {
protected:
    MD6_512 md6;
};

// MD6-128 Tests
TEST_F(MD6_128Test, OutputSize) {
    EXPECT_EQ(md6.output_size(), 16);
}

TEST_F(MD6_128Test, Name) {
    EXPECT_EQ(md6.name(), "MD6-128");
}

TEST_F(MD6_128Test, HashLength) {
    auto hash = md6.hash("test");
    EXPECT_EQ(hash.size(), 16);
}

TEST_F(MD6_128Test, Consistency) {
    auto hash1 = md6.hash("hello");
    auto hash2 = md6.hash("hello");
    EXPECT_EQ(hash1, hash2);
}

TEST_F(MD6_128Test, DifferentInputs) {
    auto hash1 = md6.hash("hello");
    auto hash2 = md6.hash("world");
    EXPECT_NE(hash1, hash2);
}

TEST_F(MD6_128Test, Verify) {
    auto hash = md6.hash("test");
    EXPECT_TRUE(md6.verify("test", hash));
    EXPECT_FALSE(md6.verify("wrong", hash));
}

// MD6-256 Tests
TEST_F(MD6_256Test, OutputSize) {
    EXPECT_EQ(md6.output_size(), 32);
}

TEST_F(MD6_256Test, Name) {
    EXPECT_EQ(md6.name(), "MD6-256");
}

TEST_F(MD6_256Test, HashLength) {
    auto hash = md6.hash("test");
    EXPECT_EQ(hash.size(), 32);
}

TEST_F(MD6_256Test, Consistency) {
    auto hash1 = md6.hash("hello");
    auto hash2 = md6.hash("hello");
    EXPECT_EQ(hash1, hash2);
}

TEST_F(MD6_256Test, DifferentInputs) {
    auto hash1 = md6.hash("hello");
    auto hash2 = md6.hash("world");
    EXPECT_NE(hash1, hash2);
}

// MD6-512 Tests
TEST_F(MD6_512Test, OutputSize) {
    EXPECT_EQ(md6.output_size(), 64);
}

TEST_F(MD6_512Test, Name) {
    EXPECT_EQ(md6.name(), "MD6-512");
}

TEST_F(MD6_512Test, HashLength) {
    auto hash = md6.hash("test");
    EXPECT_EQ(hash.size(), 64);
}

TEST_F(MD6_512Test, Consistency) {
    auto hash1 = md6.hash("hello");
    auto hash2 = md6.hash("hello");
    EXPECT_EQ(hash1, hash2);
}

TEST_F(MD6_512Test, DifferentInputs) {
    auto hash1 = md6.hash("hello");
    auto hash2 = md6.hash("world");
    EXPECT_NE(hash1, hash2);
}
