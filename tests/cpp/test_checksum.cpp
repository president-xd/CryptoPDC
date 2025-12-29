#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/checksum.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_checksum(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

// CRC16 Tests
class CRC16Test : public ::testing::Test {
protected:
    CRC16 crc16;
};

TEST_F(CRC16Test, OutputSize) {
    EXPECT_EQ(crc16.output_size(), 2);
}

TEST_F(CRC16Test, Name) {
    EXPECT_EQ(crc16.name(), "CRC16");
}

TEST_F(CRC16Test, HashLength) {
    auto hash = crc16.hash("test");
    EXPECT_EQ(hash.size(), 2);
}

TEST_F(CRC16Test, Consistency) {
    auto hash1 = crc16.hash("hello");
    auto hash2 = crc16.hash("hello");
    EXPECT_EQ(hash1, hash2);
}

TEST_F(CRC16Test, DifferentInputs) {
    auto hash1 = crc16.hash("hello");
    auto hash2 = crc16.hash("world");
    EXPECT_NE(hash1, hash2);
}

TEST_F(CRC16Test, ComputeValue) {
    std::string input = "123456789";
    uint16_t crc = CRC16::compute_value(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    // CRC16-CCITT for "123456789" should be 0x29B1
    EXPECT_EQ(crc, 0x29B1);
}

// CRC32 Tests
class CRC32Test : public ::testing::Test {
protected:
    CRC32 crc32;
};

TEST_F(CRC32Test, OutputSize) {
    EXPECT_EQ(crc32.output_size(), 4);
}

TEST_F(CRC32Test, Name) {
    EXPECT_EQ(crc32.name(), "CRC32");
}

TEST_F(CRC32Test, HashLength) {
    auto hash = crc32.hash("test");
    EXPECT_EQ(hash.size(), 4);
}

TEST_F(CRC32Test, Consistency) {
    auto hash1 = crc32.hash("hello");
    auto hash2 = crc32.hash("hello");
    EXPECT_EQ(hash1, hash2);
}

TEST_F(CRC32Test, DifferentInputs) {
    auto hash1 = crc32.hash("hello");
    auto hash2 = crc32.hash("world");
    EXPECT_NE(hash1, hash2);
}

TEST_F(CRC32Test, ComputeValue) {
    std::string input = "123456789";
    uint32_t crc = CRC32::compute_value(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    // CRC32 IEEE 802.3 for "123456789" should be 0xCBF43926
    EXPECT_EQ(crc, 0xCBF43926);
}

TEST_F(CRC32Test, EmptyString) {
    uint32_t crc = CRC32::compute_value(reinterpret_cast<const uint8_t*>(""), 0);
    EXPECT_EQ(crc, 0x00000000);
}

// Adler32 Tests
class Adler32Test : public ::testing::Test {
protected:
    Adler32 adler32;
};

TEST_F(Adler32Test, OutputSize) {
    EXPECT_EQ(adler32.output_size(), 4);
}

TEST_F(Adler32Test, Name) {
    EXPECT_EQ(adler32.name(), "Adler32");
}

TEST_F(Adler32Test, HashLength) {
    auto hash = adler32.hash("test");
    EXPECT_EQ(hash.size(), 4);
}

TEST_F(Adler32Test, Consistency) {
    auto hash1 = adler32.hash("hello");
    auto hash2 = adler32.hash("hello");
    EXPECT_EQ(hash1, hash2);
}

TEST_F(Adler32Test, DifferentInputs) {
    auto hash1 = adler32.hash("hello");
    auto hash2 = adler32.hash("world");
    EXPECT_NE(hash1, hash2);
}

TEST_F(Adler32Test, ComputeValue) {
    std::string input = "Wikipedia";
    uint32_t checksum = Adler32::compute_value(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    // Adler32 for "Wikipedia" should be 0x11E60398
    EXPECT_EQ(checksum, 0x11E60398);
}

TEST_F(Adler32Test, EmptyString) {
    uint32_t checksum = Adler32::compute_value(reinterpret_cast<const uint8_t*>(""), 0);
    EXPECT_EQ(checksum, 1);  // Adler32 of empty string is 1
}

TEST_F(Adler32Test, SingleChar) {
    uint32_t checksum = Adler32::compute_value(reinterpret_cast<const uint8_t*>("a"), 1);
    // 'a' = 97, so A = 1 + 97 = 98, B = 0 + 98 = 98
    // Result = B * 65536 + A = 98 * 65536 + 98 = 0x00620062
    EXPECT_EQ(checksum, 0x00620062);
}
