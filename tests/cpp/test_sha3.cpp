#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/sha3.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_sha3(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

// SHA3-224 Tests
class SHA3_224Test : public ::testing::Test {
protected:
    SHA3_224 sha3;
};

TEST_F(SHA3_224Test, EmptyString) {
    auto hash = sha3.hash("");
    EXPECT_EQ(to_hex_sha3(hash), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
}

TEST_F(SHA3_224Test, ABC) {
    auto hash = sha3.hash("abc");
    EXPECT_EQ(to_hex_sha3(hash), "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
}

TEST_F(SHA3_224Test, OutputSize) {
    EXPECT_EQ(sha3.output_size(), 28);
}

TEST_F(SHA3_224Test, Name) {
    EXPECT_EQ(sha3.name(), "SHA3-224");
}

TEST_F(SHA3_224Test, Verify) {
    auto hash = sha3.hash("test");
    EXPECT_TRUE(sha3.verify("test", hash));
    EXPECT_FALSE(sha3.verify("wrong", hash));
}

// SHA3-256 Tests
class SHA3_256Test : public ::testing::Test {
protected:
    SHA3_256 sha3;
};

TEST_F(SHA3_256Test, EmptyString) {
    auto hash = sha3.hash("");
    EXPECT_EQ(to_hex_sha3(hash), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

TEST_F(SHA3_256Test, ABC) {
    auto hash = sha3.hash("abc");
    EXPECT_EQ(to_hex_sha3(hash), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
}

TEST_F(SHA3_256Test, OutputSize) {
    EXPECT_EQ(sha3.output_size(), 32);
}

TEST_F(SHA3_256Test, Name) {
    EXPECT_EQ(sha3.name(), "SHA3-256");
}

TEST_F(SHA3_256Test, Verify) {
    auto hash = sha3.hash("test");
    EXPECT_TRUE(sha3.verify("test", hash));
    EXPECT_FALSE(sha3.verify("wrong", hash));
}

// SHA3-384 Tests
class SHA3_384Test : public ::testing::Test {
protected:
    SHA3_384 sha3;
};

TEST_F(SHA3_384Test, EmptyString) {
    auto hash = sha3.hash("");
    EXPECT_EQ(to_hex_sha3(hash), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
}

TEST_F(SHA3_384Test, ABC) {
    auto hash = sha3.hash("abc");
    EXPECT_EQ(to_hex_sha3(hash), "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
}

TEST_F(SHA3_384Test, OutputSize) {
    EXPECT_EQ(sha3.output_size(), 48);
}

TEST_F(SHA3_384Test, Name) {
    EXPECT_EQ(sha3.name(), "SHA3-384");
}

// SHA3-512 Tests
class SHA3_512Test : public ::testing::Test {
protected:
    SHA3_512 sha3;
};

TEST_F(SHA3_512Test, EmptyString) {
    auto hash = sha3.hash("");
    EXPECT_EQ(to_hex_sha3(hash), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
}

TEST_F(SHA3_512Test, ABC) {
    auto hash = sha3.hash("abc");
    EXPECT_EQ(to_hex_sha3(hash), "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
}

TEST_F(SHA3_512Test, OutputSize) {
    EXPECT_EQ(sha3.output_size(), 64);
}

TEST_F(SHA3_512Test, Name) {
    EXPECT_EQ(sha3.name(), "SHA3-512");
}

TEST_F(SHA3_512Test, Verify) {
    auto hash = sha3.hash("test");
    EXPECT_TRUE(sha3.verify("test", hash));
    EXPECT_FALSE(sha3.verify("wrong", hash));
}
