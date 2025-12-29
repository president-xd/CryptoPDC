#include "cryptopdc/algorithms/hash/sha512.hpp"
#include <cstring>
#include <cstdint>

namespace cryptopdc {
namespace algorithms {
namespace hash {

// SHA-512 constants - first 64 bits of the fractional parts of the cube roots of the first 80 primes
static const uint64_t SHA512_K[80] = {
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

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SIGMA1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define sigma1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

SHA512::SHA512() {}

void SHA512::compute(const uint8_t* input, size_t length, uint8_t* output) {
    // Initial hash values - first 64 bits of fractional parts of square roots of first 8 primes
    uint64_t h[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    
    // Pre-processing: adding padding bits
    // Message length in bits must be congruent to 896 mod 1024
    // Total padded length = message + 1 bit + padding + 128-bit length = multiple of 1024 bits (128 bytes)
    size_t new_len = ((((length + 16) / 128) + 1) * 128) - 16;
    uint8_t* msg = new uint8_t[new_len + 128];
    memcpy(msg, input, length);
    msg[length] = 0x80;
    
    for (size_t i = length + 1; i < new_len; i++) {
        msg[i] = 0;
    }
    
    // Append original length in bits as 128-bit big-endian (we only use lower 64 bits for simplicity)
    uint64_t bits_len = length * 8;
    // Upper 64 bits (always 0 for reasonable message lengths)
    for (int i = 0; i < 8; i++) {
        msg[new_len + i] = 0;
    }
    // Lower 64 bits
    for (int i = 0; i < 8; i++) {
        msg[new_len + 8 + i] = (bits_len >> (56 - i * 8)) & 0xFF;
    }
    
    // Process message in 1024-bit (128-byte) chunks
    for (size_t offset = 0; offset < new_len + 16; offset += 128) {
        uint64_t w[80];
        
        // Break chunk into sixteen 64-bit big-endian words
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint64_t)msg[offset + i * 8] << 56) |
                   ((uint64_t)msg[offset + i * 8 + 1] << 48) |
                   ((uint64_t)msg[offset + i * 8 + 2] << 40) |
                   ((uint64_t)msg[offset + i * 8 + 3] << 32) |
                   ((uint64_t)msg[offset + i * 8 + 4] << 24) |
                   ((uint64_t)msg[offset + i * 8 + 5] << 16) |
                   ((uint64_t)msg[offset + i * 8 + 6] << 8) |
                   ((uint64_t)msg[offset + i * 8 + 7]);
        }
        
        // Extend the sixteen 64-bit words into eighty 64-bit words
        for (int i = 16; i < 80; i++) {
            w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
        }
        
        // Initialize working variables
        uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
        
        // Compression function main loop - 80 rounds
        for (int i = 0; i < 80; i++) {
            uint64_t t1 = hh + SIGMA1(e) + CH(e, f, g) + SHA512_K[i] + w[i];
            uint64_t t2 = SIGMA0(a) + MAJ(a, b, c);
            
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        // Add to hash state
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    
    delete[] msg;
    
    // Produce the final hash value (big-endian) - 512 bits = 64 bytes
    for (int i = 0; i < 8; i++) {
        output[i * 8] = (h[i] >> 56) & 0xFF;
        output[i * 8 + 1] = (h[i] >> 48) & 0xFF;
        output[i * 8 + 2] = (h[i] >> 40) & 0xFF;
        output[i * 8 + 3] = (h[i] >> 32) & 0xFF;
        output[i * 8 + 4] = (h[i] >> 24) & 0xFF;
        output[i * 8 + 5] = (h[i] >> 16) & 0xFF;
        output[i * 8 + 6] = (h[i] >> 8) & 0xFF;
        output[i * 8 + 7] = h[i] & 0xFF;
    }
}

byte_vector SHA512::hash(const byte_vector& input) const {
    byte_vector result(64);  // 512 bits = 64 bytes
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector SHA512::hash(const std::string& input) const {
    byte_vector result(64);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool SHA512::verify(const std::string& input, const byte_vector& target_hash) const {
    auto computed = hash(input);
    return computed == target_hash;
}

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
