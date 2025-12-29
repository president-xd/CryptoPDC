#include "cryptopdc/algorithms/hash/sha3.hpp"
#include <cstring>
#include <cstdint>

namespace cryptopdc {
namespace algorithms {
namespace hash {

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// Keccak round constants
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets
static const int ROTATIONS[5][5] = {
    { 0,  1, 62, 28, 27},
    {36, 44,  6, 55, 20},
    { 3, 10, 43, 25, 39},
    {41, 45, 15, 21,  8},
    {18,  2, 61, 56, 14}
};

void SHA3Base::keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < 24; round++) {
        // Theta step
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ ROTL64(C[(x + 1) % 5], 1);
        }
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                state[x + 5 * y] ^= D[x];
            }
        }
        
        // Rho and Pi steps
        uint64_t B[25];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                B[y + 5 * ((2 * x + 3 * y) % 5)] = ROTL64(state[x + 5 * y], ROTATIONS[y][x]);
            }
        }
        
        // Chi step
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                state[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);
            }
        }
        
        // Iota step
        state[0] ^= RC[round];
    }
}

void SHA3Base::keccak_absorb(uint64_t state[25], const uint8_t* input, size_t len, size_t rate) {
    size_t rate_bytes = rate / 8;
    size_t block_size = rate_bytes;
    
    while (len >= block_size) {
        for (size_t i = 0; i < block_size / 8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++) {
                lane |= ((uint64_t)input[i * 8 + j]) << (j * 8);
            }
            state[i] ^= lane;
        }
        keccak_f1600(state);
        input += block_size;
        len -= block_size;
    }
    
    // Pad remaining input
    uint8_t padded[200] = {0};
    memcpy(padded, input, len);
    padded[len] = 0x06;  // SHA3 domain separator
    padded[block_size - 1] |= 0x80;
    
    for (size_t i = 0; i < block_size / 8; i++) {
        uint64_t lane = 0;
        for (int j = 0; j < 8; j++) {
            lane |= ((uint64_t)padded[i * 8 + j]) << (j * 8);
        }
        state[i] ^= lane;
    }
    keccak_f1600(state);
}

void SHA3Base::keccak_squeeze(uint64_t state[25], uint8_t* output, size_t output_len, size_t rate) {
    size_t rate_bytes = rate / 8;
    size_t offset = 0;
    
    while (offset < output_len) {
        size_t block_size = (output_len - offset < rate_bytes) ? (output_len - offset) : rate_bytes;
        for (size_t i = 0; i < block_size; i++) {
            output[offset + i] = (state[i / 8] >> ((i % 8) * 8)) & 0xFF;
        }
        offset += block_size;
        if (offset < output_len) {
            keccak_f1600(state);
        }
    }
}

// SHA3-224 (rate = 1152 bits, capacity = 448 bits)
SHA3_224::SHA3_224() {}

void SHA3_224::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint64_t state[25] = {0};
    keccak_absorb(state, input, length, 1152);
    keccak_squeeze(state, output, 28, 1152);
}

byte_vector SHA3_224::hash(const byte_vector& input) const {
    byte_vector result(28);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector SHA3_224::hash(const std::string& input) const {
    byte_vector result(28);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool SHA3_224::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

// SHA3-256 (rate = 1088 bits, capacity = 512 bits)
SHA3_256::SHA3_256() {}

void SHA3_256::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint64_t state[25] = {0};
    keccak_absorb(state, input, length, 1088);
    keccak_squeeze(state, output, 32, 1088);
}

byte_vector SHA3_256::hash(const byte_vector& input) const {
    byte_vector result(32);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector SHA3_256::hash(const std::string& input) const {
    byte_vector result(32);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool SHA3_256::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

// SHA3-384 (rate = 832 bits, capacity = 768 bits)
SHA3_384::SHA3_384() {}

void SHA3_384::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint64_t state[25] = {0};
    keccak_absorb(state, input, length, 832);
    keccak_squeeze(state, output, 48, 832);
}

byte_vector SHA3_384::hash(const byte_vector& input) const {
    byte_vector result(48);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector SHA3_384::hash(const std::string& input) const {
    byte_vector result(48);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool SHA3_384::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

// SHA3-512 (rate = 576 bits, capacity = 1024 bits)
SHA3_512::SHA3_512() {}

void SHA3_512::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint64_t state[25] = {0};
    keccak_absorb(state, input, length, 576);
    keccak_squeeze(state, output, 64, 576);
}

byte_vector SHA3_512::hash(const byte_vector& input) const {
    byte_vector result(64);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector SHA3_512::hash(const std::string& input) const {
    byte_vector result(64);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool SHA3_512::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
