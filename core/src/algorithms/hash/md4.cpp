#include "cryptopdc/algorithms/hash/md4.hpp"
#include <cstring>
#include <cstdint>

namespace cryptopdc {
namespace algorithms {
namespace hash {

#define MD4_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD4_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define MD4_ROUND1(a, b, c, d, x, s) \
    a = MD4_ROTL((a + MD4_F(b, c, d) + x), s)

#define MD4_ROUND2(a, b, c, d, x, s) \
    a = MD4_ROTL((a + MD4_G(b, c, d) + x + 0x5A827999), s)

#define MD4_ROUND3(a, b, c, d, x, s) \
    a = MD4_ROTL((a + MD4_H(b, c, d) + x + 0x6ED9EBA1), s)

MD4::MD4() {}

void MD4::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;
    
    // Pre-processing: adding padding bits
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    uint8_t* msg = new uint8_t[new_len + 64];
    memcpy(msg, input, length);
    msg[length] = 0x80;
    
    for (size_t i = length + 1; i < new_len; i++) {
        msg[i] = 0;
    }
    
    // Append original length in bits
    uint64_t bits_len = length * 8;
    memcpy(msg + new_len, &bits_len, 8);
    
    // Process message in 512-bit chunks
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t* X = (uint32_t*)(msg + offset);
        
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        
        // Round 1
        MD4_ROUND1(a, b, c, d, X[0],  3);
        MD4_ROUND1(d, a, b, c, X[1],  7);
        MD4_ROUND1(c, d, a, b, X[2],  11);
        MD4_ROUND1(b, c, d, a, X[3],  19);
        MD4_ROUND1(a, b, c, d, X[4],  3);
        MD4_ROUND1(d, a, b, c, X[5],  7);
        MD4_ROUND1(c, d, a, b, X[6],  11);
        MD4_ROUND1(b, c, d, a, X[7],  19);
        MD4_ROUND1(a, b, c, d, X[8],  3);
        MD4_ROUND1(d, a, b, c, X[9],  7);
        MD4_ROUND1(c, d, a, b, X[10], 11);
        MD4_ROUND1(b, c, d, a, X[11], 19);
        MD4_ROUND1(a, b, c, d, X[12], 3);
        MD4_ROUND1(d, a, b, c, X[13], 7);
        MD4_ROUND1(c, d, a, b, X[14], 11);
        MD4_ROUND1(b, c, d, a, X[15], 19);
        
        // Round 2
        MD4_ROUND2(a, b, c, d, X[0],  3);
        MD4_ROUND2(d, a, b, c, X[4],  5);
        MD4_ROUND2(c, d, a, b, X[8],  9);
        MD4_ROUND2(b, c, d, a, X[12], 13);
        MD4_ROUND2(a, b, c, d, X[1],  3);
        MD4_ROUND2(d, a, b, c, X[5],  5);
        MD4_ROUND2(c, d, a, b, X[9],  9);
        MD4_ROUND2(b, c, d, a, X[13], 13);
        MD4_ROUND2(a, b, c, d, X[2],  3);
        MD4_ROUND2(d, a, b, c, X[6],  5);
        MD4_ROUND2(c, d, a, b, X[10], 9);
        MD4_ROUND2(b, c, d, a, X[14], 13);
        MD4_ROUND2(a, b, c, d, X[3],  3);
        MD4_ROUND2(d, a, b, c, X[7],  5);
        MD4_ROUND2(c, d, a, b, X[11], 9);
        MD4_ROUND2(b, c, d, a, X[15], 13);
        
        // Round 3
        MD4_ROUND3(a, b, c, d, X[0],  3);
        MD4_ROUND3(d, a, b, c, X[8],  9);
        MD4_ROUND3(c, d, a, b, X[4],  11);
        MD4_ROUND3(b, c, d, a, X[12], 15);
        MD4_ROUND3(a, b, c, d, X[2],  3);
        MD4_ROUND3(d, a, b, c, X[10], 9);
        MD4_ROUND3(c, d, a, b, X[6],  11);
        MD4_ROUND3(b, c, d, a, X[14], 15);
        MD4_ROUND3(a, b, c, d, X[1],  3);
        MD4_ROUND3(d, a, b, c, X[9],  9);
        MD4_ROUND3(c, d, a, b, X[5],  11);
        MD4_ROUND3(b, c, d, a, X[13], 15);
        MD4_ROUND3(a, b, c, d, X[3],  3);
        MD4_ROUND3(d, a, b, c, X[11], 9);
        MD4_ROUND3(c, d, a, b, X[7],  11);
        MD4_ROUND3(b, c, d, a, X[15], 15);
        
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }
    
    delete[] msg;
    
    // Output hash
    memcpy(output, &h0, 4);
    memcpy(output + 4, &h1, 4);
    memcpy(output + 8, &h2, 4);
    memcpy(output + 12, &h3, 4);
}

byte_vector MD4::hash(const byte_vector& input) const {
    byte_vector result(16);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector MD4::hash(const std::string& input) const {
    byte_vector result(16);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool MD4::verify(const std::string& input, const byte_vector& target_hash) const {
    auto computed = hash(input);
    return computed == target_hash;
}

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
