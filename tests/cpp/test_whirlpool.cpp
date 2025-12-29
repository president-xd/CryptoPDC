#include <gtest/gtest.h>
#include "cryptopdc/algorithms/hash/whirlpool.hpp"
#include <string>
#include <sstream>
#include <iomanip>

using namespace cryptopdc::algorithms::hash;

std::string to_hex_whirlpool(const cryptopdc::byte_vector& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

class WhirlpoolTest : public ::testing::Test {
protected:
    Whirlpool whirlpool;
};

TEST_F(WhirlpoolTest, OutputSize) {
    EXPECT_EQ(whirlpool.output_size(), 64);
}

TEST_F(WhirlpoolTest, Name) {
    EXPECT_EQ(whirlpool.name(), "Whirlpool");
}

TEST_F(WhirlpoolTest, HashLength) {
    auto hash = whirlpool.hash("test");
    EXPECT_EQ(hash.size(), 64);
}

TEST_F(WhirlpoolTest, Consistency) {
    auto hash1 = whirlpool.hash("hello");
    auto hash2 = whirlpool.hash("hello");
    EXPECT_EQ(hash1, hash2);
}

TEST_F(WhirlpoolTest, DifferentInputs) {
    auto hash1 = whirlpool.hash("hello");
    auto hash2 = whirlpool.hash("world");
    EXPECT_NE(hash1, hash2);
}

// Official Whirlpool test vectors from ISO/IEC 10118-3:2004
TEST_F(WhirlpoolTest, EmptyString) {
    auto hash = whirlpool.hash("");
    EXPECT_EQ(to_hex_whirlpool(hash), 
        "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7"
        "3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
}

TEST_F(WhirlpoolTest, SingleChar_a) {
    auto hash = whirlpool.hash("a");
    EXPECT_EQ(to_hex_whirlpool(hash), 
        "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42"
        "d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a");
}

TEST_F(WhirlpoolTest, ABC) {
    auto hash = whirlpool.hash("abc");
    EXPECT_EQ(to_hex_whirlpool(hash), 
        "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c"
        "7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5");
}

TEST_F(WhirlpoolTest, MessageDigest) {
    auto hash = whirlpool.hash("message digest");
    EXPECT_EQ(to_hex_whirlpool(hash), 
        "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b"
        "8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e");
}

TEST_F(WhirlpoolTest, Alphabet) {
    auto hash = whirlpool.hash("abcdefghijklmnopqrstuvwxyz");
    EXPECT_EQ(to_hex_whirlpool(hash), 
        "f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b"
        "08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b");
}

TEST_F(WhirlpoolTest, AlphanumericUpperLower) {
    auto hash = whirlpool.hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    EXPECT_EQ(to_hex_whirlpool(hash), 
        "dc37e008cf9ee69bf11f00ed9aba26901dd7c28cdec066cc6af42e40f82f3a1e"
        "08eba26629129d8fb7cb57211b9281a65517cc879d7b962142c65f5a7af01467");
}

TEST_F(WhirlpoolTest, NumericRepeated) {
    // 8 repetitions of "1234567890"
    auto hash = whirlpool.hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    EXPECT_EQ(to_hex_whirlpool(hash), 
        "466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb601429"
        "4d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b");
}

TEST_F(WhirlpoolTest, TheLazyDog) {
    auto hash = whirlpool.hash("The quick brown fox jumps over the lazy dog");
    EXPECT_EQ(to_hex_whirlpool(hash), 
        "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725f"
        "d2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35");
}

TEST_F(WhirlpoolTest, TheLazyDogPeriod) {
    auto hash = whirlpool.hash("The quick brown fox jumps over the lazy dog.");
    EXPECT_EQ(to_hex_whirlpool(hash), 
        "87a7ff096082e3ffeb86db10feb91c5af36c2c71bc426fe310ce662e0338223e"
        "217def0eab0b02b80eecf875657802bc5965e48f5c0a05467756f0d3f396faba");
}

// Test with binary data
TEST_F(WhirlpoolTest, BinaryData) {
    std::vector<uint8_t> binary_data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    auto hash = whirlpool.hash(binary_data);
    EXPECT_EQ(hash.size(), 64);
}

// Test hash computation consistency with byte vector input
TEST_F(WhirlpoolTest, ByteVectorConsistency) {
    std::string str = "test";
    std::vector<uint8_t> vec(str.begin(), str.end());
    
    auto hash1 = whirlpool.hash(str);
    auto hash2 = whirlpool.hash(vec);
    
    EXPECT_EQ(hash1, hash2);
}
