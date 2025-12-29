#include "cryptopdc/algorithms/hash/sha224.hpp"
#include <cstring>
#include <cstdint>

namespace cryptopdc {
namespace algorithms {
namespace hash {

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA224::SHA224() {}

void SHA224::compute(const uint8_t* input, size_t length, uint8_t* output) {
    // SHA-224 initial hash values (different from SHA-256)
    uint32_t h0 = 0xc1059ed8;
    uint32_t h1 = 0x367cd507;
    uint32_t h2 = 0x3070dd17;
    uint32_t h3 = 0xf70e5939;
    uint32_t h4 = 0xffc00b31;
    uint32_t h5 = 0x68581511;
    uint32_t h6 = 0x64f98fa7;
    uint32_t h7 = 0xbefa4fa4;
    
    // Pre-processing: adding padding bits
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    uint8_t* msg = new uint8_t[new_len + 64];
    memcpy(msg, input, length);
    msg[length] = 0x80;
    for (size_t i = length + 1; i < new_len; i++) {
        msg[i] = 0;
    }
    
    // Append length in big-endian
    uint64_t bits_len = length * 8;
    for (int i = 0; i < 8; i++) {
        msg[new_len + i] = (bits_len >> (56 - i * 8)) & 0xFF;
    }
    
    // Process each 512-bit chunk
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t w[64];
        
        // Break chunk into sixteen 32-bit big-endian words
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[offset + i*4] << 24) | (msg[offset + i*4 + 1] << 16) |
                   (msg[offset + i*4 + 2] << 8) | msg[offset + i*4 + 3];
        }
        
        // Extend the sixteen 32-bit words into sixty-four 32-bit words
        for (int i = 16; i < 64; i++) {
            w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
        }
        
        // Initialize working variables
        uint32_t a = h0, b = h1, c = h2, d = h3;
        uint32_t e = h4, f = h5, g = h6, h = h7;
        
        // Main loop
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        
        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += h;
    }
    
    delete[] msg;
    
    // Output only first 28 bytes (224 bits)
    for (int i = 0; i < 4; i++) output[i] = (h0 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[4 + i] = (h1 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[8 + i] = (h2 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[12 + i] = (h3 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[16 + i] = (h4 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[20 + i] = (h5 >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) output[24 + i] = (h6 >> (24 - i * 8)) & 0xFF;
    // h7 is not included (truncated)
}

byte_vector SHA224::hash(const byte_vector& input) const {
    byte_vector result(28);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector SHA224::hash(const std::string& input) const {
    byte_vector result(28);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool SHA224::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
