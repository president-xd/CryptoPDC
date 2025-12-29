#include "cryptopdc/algorithms/hash/checksum.hpp"
#include <cstring>
#include <cstdint>

namespace cryptopdc {
namespace algorithms {
namespace hash {

// CRC16 lookup table (CRC-16-CCITT polynomial 0x1021)
static uint16_t crc16_table[256];
static bool crc16_table_init = false;

static void init_crc16_table() {
    if (crc16_table_init) return;
    for (int i = 0; i < 256; i++) {
        uint16_t crc = i << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc <<= 1;
        }
        crc16_table[i] = crc;
    }
    crc16_table_init = true;
}

// CRC32 lookup table (IEEE 802.3 polynomial)
static uint32_t crc32_table[256];
static bool crc32_table_init = false;

static void init_crc32_table() {
    if (crc32_table_init) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
    crc32_table_init = true;
}

// CRC16 Implementation
CRC16::CRC16() { init_crc16_table(); }

uint16_t CRC16::compute_value(const uint8_t* input, size_t length) {
    init_crc16_table();
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = (crc << 8) ^ crc16_table[((crc >> 8) ^ input[i]) & 0xFF];
    }
    return crc;
}

void CRC16::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint16_t crc = compute_value(input, length);
    output[0] = (crc >> 8) & 0xFF;
    output[1] = crc & 0xFF;
}

byte_vector CRC16::hash(const byte_vector& input) const {
    byte_vector result(2);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector CRC16::hash(const std::string& input) const {
    byte_vector result(2);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool CRC16::verify(const std::string& input, const byte_vector& target_hash) const {
    auto computed = hash(input);
    return computed == target_hash;
}

// CRC32 Implementation
CRC32::CRC32() { init_crc32_table(); }

uint32_t CRC32::compute_value(const uint8_t* input, size_t length) {
    init_crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ input[i]) & 0xFF];
    }
    return ~crc;
}

void CRC32::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t crc = compute_value(input, length);
    memcpy(output, &crc, 4);
}

byte_vector CRC32::hash(const byte_vector& input) const {
    byte_vector result(4);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector CRC32::hash(const std::string& input) const {
    byte_vector result(4);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool CRC32::verify(const std::string& input, const byte_vector& target_hash) const {
    auto computed = hash(input);
    return computed == target_hash;
}

// Adler32 Implementation
Adler32::Adler32() {}

uint32_t Adler32::compute_value(const uint8_t* input, size_t length) {
    const uint32_t MOD_ADLER = 65521;
    uint32_t a = 1, b = 0;
    
    for (size_t i = 0; i < length; i++) {
        a = (a + input[i]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    
    return (b << 16) | a;
}

void Adler32::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t adler = compute_value(input, length);
    memcpy(output, &adler, 4);
}

byte_vector Adler32::hash(const byte_vector& input) const {
    byte_vector result(4);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector Adler32::hash(const std::string& input) const {
    byte_vector result(4);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool Adler32::verify(const std::string& input, const byte_vector& target_hash) const {
    auto computed = hash(input);
    return computed == target_hash;
}

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
