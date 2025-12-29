#include "cryptopdc/algorithms/hash/md6.hpp"
#include <cstring>
#include <cstdint>
#include <vector>

namespace cryptopdc {
namespace algorithms {
namespace hash {

// MD6 Q constant (fractional part of sqrt of first 15 primes)
const uint64_t MD6Base::Q[15] = {
    0x7311c2812425cfa0ULL, 0x6432286434aac8e7ULL, 0xb60450e9ef68b7c1ULL,
    0xe8fb23908d9f06f1ULL, 0xdd2e76cba691e5bfULL, 0x0cd0d63b2c30bc41ULL,
    0x1f8ccf6823058f8aULL, 0x54e5ed5b88e3775dULL, 0x4ad12aae0a6d6031ULL,
    0x3e7f16bb88222e0dULL, 0x8af8671d3fb50c2cULL, 0x995ad1178bd25c31ULL,
    0xc878c1dd04c4b633ULL, 0x3b72066c7a1552acULL, 0x0d6f3522631effcbULL
};

// MD6 shift amounts
const int MD6Base::S[16] = {
    10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12
};

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

void MD6Base::md6_compress(uint64_t* C, const uint64_t* N, int r) {
    // MD6 compression function
    // N = 89 words input, produces 16 words output in C
    const int n = 89;  // Input size in words
    const int c = 16;  // Output size in words
    
    // Copy input to working array A
    uint64_t A[89 + 16 * 168];  // Maximum size for 168 rounds
    memcpy(A, N, n * sizeof(uint64_t));
    
    // Round function
    int t0 = 17, t1 = 18, t2 = 21, t3 = 31, t4 = 67;
    
    for (int j = 0; j < r * c; j++) {
        int i = n + j;
        uint64_t x = A[i - n] ^ A[i - t0];
        x ^= (A[i - t1] & A[i - t2]);
        x ^= (A[i - t3] & A[i - t4]);
        x ^= (x >> S[j % 16]);
        A[i] = x ^ Q[j % 15];
    }
    
    // Copy output
    for (int i = 0; i < c; i++) {
        C[i] = A[n + r * c - c + i];
    }
}

void MD6Base::md6_hash(const uint8_t* input, size_t length, uint8_t* output, size_t d) {
    // Simplified MD6 for single-block messages
    const int c = 16;  // 1024-bit chaining value
    const int n = 89;  // Input block size in 64-bit words
    const int r = 80;  // Number of rounds (default)
    
    // Initialize N array
    uint64_t N[89] = {0};
    
    // Copy Q constants
    memcpy(N, Q, 15 * sizeof(uint64_t));
    
    // Set K (key) to zero - indices 15-22
    // Already zero
    
    // Set U (unique ID) at index 23
    N[23] = ((uint64_t)r << 48) | ((uint64_t)0 << 40) | ((uint64_t)0 << 32) | 
            ((uint64_t)4 << 24) | ((uint64_t)64 << 16) | (uint64_t)d;
    
    // Set V (control word) at index 24
    N[24] = 0;  // Sequential mode, level 0
    
    // Copy message data starting at index 25
    size_t msg_words = (length + 7) / 8;
    if (msg_words > 64) msg_words = 64;  // Limit for single block
    
    for (size_t i = 0; i < msg_words && i < 64; i++) {
        uint64_t word = 0;
        for (int j = 0; j < 8 && (i * 8 + j) < length; j++) {
            word |= ((uint64_t)input[i * 8 + j]) << (j * 8);
        }
        N[25 + i] = word;
    }
    
    // Add padding
    if (length < 512) {
        size_t pad_idx = 25 + (length / 8);
        size_t pad_bit = length % 8;
        N[pad_idx] |= ((uint64_t)0x80) << (pad_bit * 8);
    }
    
    // Compress
    uint64_t C[16];
    md6_compress(C, N, r);
    
    // Extract output (d bits)
    size_t out_bytes = d / 8;
    for (size_t i = 0; i < out_bytes && i < 64; i++) {
        output[i] = (C[c - (out_bytes / 8) + i / 8] >> ((i % 8) * 8)) & 0xFF;
    }
}

// MD6-128
MD6_128::MD6_128() {}

void MD6_128::compute(const uint8_t* input, size_t length, uint8_t* output) {
    md6_hash(input, length, output, 128);
}

byte_vector MD6_128::hash(const byte_vector& input) const {
    byte_vector result(16);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector MD6_128::hash(const std::string& input) const {
    byte_vector result(16);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool MD6_128::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

// MD6-256
MD6_256::MD6_256() {}

void MD6_256::compute(const uint8_t* input, size_t length, uint8_t* output) {
    md6_hash(input, length, output, 256);
}

byte_vector MD6_256::hash(const byte_vector& input) const {
    byte_vector result(32);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector MD6_256::hash(const std::string& input) const {
    byte_vector result(32);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool MD6_256::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

// MD6-512
MD6_512::MD6_512() {}

void MD6_512::compute(const uint8_t* input, size_t length, uint8_t* output) {
    md6_hash(input, length, output, 512);
}

byte_vector MD6_512::hash(const byte_vector& input) const {
    byte_vector result(64);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector MD6_512::hash(const std::string& input) const {
    byte_vector result(64);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool MD6_512::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
