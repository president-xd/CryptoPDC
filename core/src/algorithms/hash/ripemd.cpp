#include "cryptopdc/algorithms/hash/ripemd.hpp"
#include <cstring>
#include <cstdint>

namespace cryptopdc {
namespace algorithms {
namespace hash {

// RIPEMD helper macros
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// RIPEMD-160 functions
#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z) (((x) | ~(y)) ^ (z))
#define I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z) ((x) ^ ((y) | ~(z)))

// RIPEMD-160 constants
static const uint32_t RMD160_K[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
static const uint32_t RMD160_KK[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};

static const int RMD160_R[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

static const int RMD160_RR[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

static const int RMD160_S[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

static const int RMD160_SS[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

RIPEMD160::RIPEMD160() {}

void RIPEMD160::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    uint8_t* msg = new uint8_t[new_len + 64];
    memcpy(msg, input, length);
    msg[length] = 0x80;
    for (size_t i = length + 1; i < new_len; i++) msg[i] = 0;
    uint64_t bits_len = length * 8;
    memcpy(msg + new_len, &bits_len, 8);
    
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t* X = (uint32_t*)(msg + offset);
        
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        uint32_t aa = h0, bb = h1, cc = h2, dd = h3, ee = h4;
        
        for (int j = 0; j < 80; j++) {
            uint32_t f, ff, t;
            int jj = j / 16;
            
            switch (jj) {
                case 0: f = F(b, c, d); ff = J(bb, cc, dd); break;
                case 1: f = G(b, c, d); ff = I(bb, cc, dd); break;
                case 2: f = H(b, c, d); ff = H(bb, cc, dd); break;
                case 3: f = I(b, c, d); ff = G(bb, cc, dd); break;
                default: f = J(b, c, d); ff = F(bb, cc, dd); break;
            }
            
            t = ROTL32(a + f + X[RMD160_R[j]] + RMD160_K[jj], RMD160_S[j]) + e;
            a = e; e = d; d = ROTL32(c, 10); c = b; b = t;
            
            t = ROTL32(aa + ff + X[RMD160_RR[j]] + RMD160_KK[jj], RMD160_SS[j]) + ee;
            aa = ee; ee = dd; dd = ROTL32(cc, 10); cc = bb; bb = t;
        }
        
        uint32_t t = h1 + c + dd;
        h1 = h2 + d + ee; h2 = h3 + e + aa; h3 = h4 + a + bb; h4 = h0 + b + cc; h0 = t;
    }
    
    delete[] msg;
    
    memcpy(output, &h0, 4);
    memcpy(output + 4, &h1, 4);
    memcpy(output + 8, &h2, 4);
    memcpy(output + 12, &h3, 4);
    memcpy(output + 16, &h4, 4);
}

byte_vector RIPEMD160::hash(const byte_vector& input) const {
    byte_vector result(20);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector RIPEMD160::hash(const std::string& input) const {
    byte_vector result(20);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool RIPEMD160::verify(const std::string& input, const byte_vector& target_hash) const {
    auto computed = hash(input);
    return computed == target_hash;
}

// RIPEMD-128
RIPEMD128::RIPEMD128() {}

void RIPEMD128::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476;
    
    static const uint32_t K[4] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC};
    static const uint32_t KK[4] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x00000000};
    
    static const int r[64] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
    };
    
    static const int rr[64] = {
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
    };
    
    static const int s[64] = {
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
    };
    
    static const int ss[64] = {
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
    };
    
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    uint8_t* msg = new uint8_t[new_len + 64];
    memcpy(msg, input, length);
    msg[length] = 0x80;
    for (size_t i = length + 1; i < new_len; i++) msg[i] = 0;
    uint64_t bits_len = length * 8;
    memcpy(msg + new_len, &bits_len, 8);
    
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t* X = (uint32_t*)(msg + offset);
        
        uint32_t a = h0, b = h1, c = h2, d = h3;
        uint32_t aa = h0, bb = h1, cc = h2, dd = h3;
        
        for (int j = 0; j < 64; j++) {
            uint32_t f, ff, t;
            int jj = j / 16;
            
            switch (jj) {
                case 0: f = F(b, c, d); ff = I(bb, cc, dd); break;
                case 1: f = G(b, c, d); ff = H(bb, cc, dd); break;
                case 2: f = H(b, c, d); ff = G(bb, cc, dd); break;
                default: f = I(b, c, d); ff = F(bb, cc, dd); break;
            }
            
            t = ROTL32(a + f + X[r[j]] + K[jj], s[j]);
            a = d; d = c; c = b; b = t;
            
            t = ROTL32(aa + ff + X[rr[j]] + KK[jj], ss[j]);
            aa = dd; dd = cc; cc = bb; bb = t;
        }
        
        uint32_t t = h1 + c + dd;
        h1 = h2 + d + aa; h2 = h3 + a + bb; h3 = h0 + b + cc; h0 = t;
    }
    
    delete[] msg;
    
    memcpy(output, &h0, 4);
    memcpy(output + 4, &h1, 4);
    memcpy(output + 8, &h2, 4);
    memcpy(output + 12, &h3, 4);
}

byte_vector RIPEMD128::hash(const byte_vector& input) const {
    byte_vector result(16);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector RIPEMD128::hash(const std::string& input) const {
    byte_vector result(16);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool RIPEMD128::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

// RIPEMD-256 (extended RIPEMD-128)
RIPEMD256::RIPEMD256() {}

void RIPEMD256::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476;
    uint32_t h4 = 0x76543210, h5 = 0xFEDCBA98, h6 = 0x89ABCDEF, h7 = 0x01234567;
    
    static const uint32_t K[4] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC};
    static const uint32_t KK[4] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x00000000};
    
    static const int r[64] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
    };
    
    static const int rr[64] = {
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
    };
    
    static const int s[64] = {
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
    };
    
    static const int ss[64] = {
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
    };
    
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    uint8_t* msg = new uint8_t[new_len + 64];
    memcpy(msg, input, length);
    msg[length] = 0x80;
    for (size_t i = length + 1; i < new_len; i++) msg[i] = 0;
    uint64_t bits_len = length * 8;
    memcpy(msg + new_len, &bits_len, 8);
    
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t* X = (uint32_t*)(msg + offset);
        
        uint32_t a = h0, b = h1, c = h2, d = h3;
        uint32_t aa = h4, bb = h5, cc = h6, dd = h7;
        uint32_t t;
        
        for (int j = 0; j < 64; j++) {
            uint32_t f, ff;
            int jj = j / 16;
            
            switch (jj) {
                case 0: f = F(b, c, d); ff = I(bb, cc, dd); break;
                case 1: f = G(b, c, d); ff = H(bb, cc, dd); break;
                case 2: f = H(b, c, d); ff = G(bb, cc, dd); break;
                default: f = I(b, c, d); ff = F(bb, cc, dd); break;
            }
            
            t = ROTL32(a + f + X[r[j]] + K[jj], s[j]);
            a = d; d = c; c = b; b = t;
            
            t = ROTL32(aa + ff + X[rr[j]] + KK[jj], ss[j]);
            aa = dd; dd = cc; cc = bb; bb = t;
            
            // Swap at end of each round
            if (j == 15) { t = a; a = aa; aa = t; }
            else if (j == 31) { t = b; b = bb; bb = t; }
            else if (j == 47) { t = c; c = cc; cc = t; }
            else if (j == 63) { t = d; d = dd; dd = t; }
        }
        
        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += aa; h5 += bb; h6 += cc; h7 += dd;
    }
    
    delete[] msg;
    
    memcpy(output, &h0, 4);
    memcpy(output + 4, &h1, 4);
    memcpy(output + 8, &h2, 4);
    memcpy(output + 12, &h3, 4);
    memcpy(output + 16, &h4, 4);
    memcpy(output + 20, &h5, 4);
    memcpy(output + 24, &h6, 4);
    memcpy(output + 28, &h7, 4);
}

byte_vector RIPEMD256::hash(const byte_vector& input) const {
    byte_vector result(32);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector RIPEMD256::hash(const std::string& input) const {
    byte_vector result(32);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool RIPEMD256::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

// RIPEMD-320 (extended RIPEMD-160)
RIPEMD320::RIPEMD320() {}

void RIPEMD320::compute(const uint8_t* input, size_t length, uint8_t* output) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    uint32_t h5 = 0x76543210, h6 = 0xFEDCBA98, h7 = 0x89ABCDEF, h8 = 0x01234567, h9 = 0x3C2D1E0F;
    
    size_t new_len = ((((length + 8) / 64) + 1) * 64) - 8;
    uint8_t* msg = new uint8_t[new_len + 64];
    memcpy(msg, input, length);
    msg[length] = 0x80;
    for (size_t i = length + 1; i < new_len; i++) msg[i] = 0;
    uint64_t bits_len = length * 8;
    memcpy(msg + new_len, &bits_len, 8);
    
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t* X = (uint32_t*)(msg + offset);
        
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        uint32_t aa = h5, bb = h6, cc = h7, dd = h8, ee = h9;
        
        for (int j = 0; j < 80; j++) {
            uint32_t f, ff, t;
            int jj = j / 16;
            
            switch (jj) {
                case 0: f = F(b, c, d); ff = J(bb, cc, dd); break;
                case 1: f = G(b, c, d); ff = I(bb, cc, dd); break;
                case 2: f = H(b, c, d); ff = H(bb, cc, dd); break;
                case 3: f = I(b, c, d); ff = G(bb, cc, dd); break;
                default: f = J(b, c, d); ff = F(bb, cc, dd); break;
            }
            
            t = ROTL32(a + f + X[RMD160_R[j]] + RMD160_K[jj], RMD160_S[j]) + e;
            a = e; e = d; d = ROTL32(c, 10); c = b; b = t;
            
            t = ROTL32(aa + ff + X[RMD160_RR[j]] + RMD160_KK[jj], RMD160_SS[j]) + ee;
            aa = ee; ee = dd; dd = ROTL32(cc, 10); cc = bb; bb = t;
            
            // Swap at end of each round
            if (j == 15) { t = b; b = bb; bb = t; }
            else if (j == 31) { t = d; d = dd; dd = t; }
            else if (j == 47) { t = a; a = aa; aa = t; }
            else if (j == 63) { t = c; c = cc; cc = t; }
            else if (j == 79) { t = e; e = ee; ee = t; }
        }
        
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
        h5 += aa; h6 += bb; h7 += cc; h8 += dd; h9 += ee;
    }
    
    delete[] msg;
    
    memcpy(output, &h0, 4);
    memcpy(output + 4, &h1, 4);
    memcpy(output + 8, &h2, 4);
    memcpy(output + 12, &h3, 4);
    memcpy(output + 16, &h4, 4);
    memcpy(output + 20, &h5, 4);
    memcpy(output + 24, &h6, 4);
    memcpy(output + 28, &h7, 4);
    memcpy(output + 32, &h8, 4);
    memcpy(output + 36, &h9, 4);
}

byte_vector RIPEMD320::hash(const byte_vector& input) const {
    byte_vector result(40);
    compute(input.data(), input.size(), result.data());
    return result;
}

byte_vector RIPEMD320::hash(const std::string& input) const {
    byte_vector result(40);
    compute(reinterpret_cast<const uint8_t*>(input.data()), input.size(), result.data());
    return result;
}

bool RIPEMD320::verify(const std::string& input, const byte_vector& target_hash) const {
    return hash(input) == target_hash;
}

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
