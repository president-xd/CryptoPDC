#include "cryptopdc/algorithms/hash/sha1.hpp"
#include <cstring>
#include <cstdint>

namespace cryptopdc {
namespace algorithms {
namespace hash {

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))

SHA1::SHA1() {}

void SHA1::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t h[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE,
        0x10325476, 0xC3D2E1F0
    };
    
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    uint8_t* msg = new uint8_t[new_len + 64];
    memcpy(msg, input, length);
    msg[length] = 0x80;
    
    for (size_t i = length + 1; i < new_len; i++) {
        msg[i] = 0;
    }
    
    uint64_t bits_len = length * 8;
    for (int i = 0; i < 8; i++) {
        msg[new_len + i] = (bits_len >> (56 - i * 8)) & 0xFF;
    }
    
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t w[80];
        
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[offset + i * 4] << 24) |
                   (msg[offset + i * 4 + 1] << 16) |
                   (msg[offset + i * 4 + 2] << 8) |
                   (msg[offset + i * 4 + 3]);
        }
        
        for (int i = 16; i < 80; i++) {
            w[i] = ROTLEFT((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
        }
        
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            
            uint32_t temp = ROTLEFT(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = ROTLEFT(b, 30);
            b = a;
            a = temp;
        }
        
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }
    
    delete[] msg;
    
    for (int i = 0; i < 5; i++) {
        output[i * 4] = (h[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        output[i * 4 + 3] = h[i] & 0xFF;
    }
}

byte_vector SHA1::hash(const byte_vector& input) const {
    byte_vector result(20);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector SHA1::hash(const std::string& input) const {
    byte_vector result(20);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool SHA1::verify(const std::string& input, const byte_vector& target_hash) const {
    auto computed = hash(input);
    return computed == target_hash;
}

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
