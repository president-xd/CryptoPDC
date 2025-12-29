#include "cryptopdc/algorithms/hash/sha384.hpp"
#include <cstring>
#include <cstdint>

namespace cryptopdc {
namespace algorithms {
namespace hash {

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_64(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define EP1_64(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SIG0_64(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SIG1_64(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

SHA384::SHA384() {}

void SHA384::compute(const uint8_t* input, size_t length, uint8_t* output) {
    // SHA-384 initial hash values (different from SHA-512)
    uint64_t h0 = 0xcbbb9d5dc1059ed8ULL;
    uint64_t h1 = 0x629a292a367cd507ULL;
    uint64_t h2 = 0x9159015a3070dd17ULL;
    uint64_t h3 = 0x152fecd8f70e5939ULL;
    uint64_t h4 = 0x67332667ffc00b31ULL;
    uint64_t h5 = 0x8eb44a8768581511ULL;
    uint64_t h6 = 0xdb0c2e0d64f98fa7ULL;
    uint64_t h7 = 0x47b5481dbefa4fa4ULL;
    
    // Pre-processing: adding padding bits
    size_t new_len = ((((length + 16) / 128) + 1) * 128) - 16;
    uint8_t* msg = new uint8_t[new_len + 128];
    memcpy(msg, input, length);
    msg[length] = 0x80;
    for (size_t i = length + 1; i < new_len; i++) {
        msg[i] = 0;
    }
    
    // Append length in big-endian (128-bit length, but we only use lower 64 bits)
    for (int i = 0; i < 8; i++) {
        msg[new_len + i] = 0;  // Upper 64 bits of length (0 for our purposes)
    }
    uint64_t bits_len = length * 8;
    for (int i = 0; i < 8; i++) {
        msg[new_len + 8 + i] = (bits_len >> (56 - i * 8)) & 0xFF;
    }
    
    // Process each 1024-bit chunk
    for (size_t offset = 0; offset < new_len; offset += 128) {
        uint64_t w[80];
        
        // Break chunk into sixteen 64-bit big-endian words
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint64_t)msg[offset + i*8] << 56) |
                   ((uint64_t)msg[offset + i*8 + 1] << 48) |
                   ((uint64_t)msg[offset + i*8 + 2] << 40) |
                   ((uint64_t)msg[offset + i*8 + 3] << 32) |
                   ((uint64_t)msg[offset + i*8 + 4] << 24) |
                   ((uint64_t)msg[offset + i*8 + 5] << 16) |
                   ((uint64_t)msg[offset + i*8 + 6] << 8) |
                   (uint64_t)msg[offset + i*8 + 7];
        }
        
        // Extend the sixteen 64-bit words into eighty 64-bit words
        for (int i = 16; i < 80; i++) {
            w[i] = SIG1_64(w[i-2]) + w[i-7] + SIG0_64(w[i-15]) + w[i-16];
        }
        
        // Initialize working variables
        uint64_t a = h0, b = h1, c = h2, d = h3;
        uint64_t e = h4, f = h5, g = h6, h = h7;
        
        // Main loop
        for (int i = 0; i < 80; i++) {
            uint64_t t1 = h + EP1_64(e) + CH64(e, f, g) + K[i] + w[i];
            uint64_t t2 = EP0_64(a) + MAJ64(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        
        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += h;
    }
    
    delete[] msg;
    
    // Output only first 48 bytes (384 bits) - 6 words instead of 8
    for (int i = 0; i < 8; i++) output[i] = (h0 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[8 + i] = (h1 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[16 + i] = (h2 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[24 + i] = (h3 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[32 + i] = (h4 >> (56 - i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++) output[40 + i] = (h5 >> (56 - i * 8)) & 0xFF;
    // h6 and h7 are not included (truncated)
}

byte_vector SHA384::hash(const byte_vector& input) const {
    byte_vector result(48);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector SHA384::hash(const std::string& input) const {
    byte_vector result(48);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool SHA384::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
