#ifndef CRYPTOPDC_SHA3_HPP
#define CRYPTOPDC_SHA3_HPP

#include "cryptopdc/algorithms/algorithm_base.hpp"

namespace cryptopdc {
namespace algorithms {
namespace hash {

// Base SHA3 class with Keccak sponge construction
class SHA3Base {
protected:
    static void keccak_f1600(uint64_t state[25]);
    static void keccak_absorb(uint64_t state[25], const uint8_t* input, size_t len, size_t rate);
    static void keccak_squeeze(uint64_t state[25], uint8_t* output, size_t output_len, size_t rate);
};

class SHA3_224 : public HashAlgorithm, private SHA3Base {
public:
    SHA3_224();
    
    std::string name() const override { return "SHA3-224"; }
    size_t output_size() const override { return 28; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

class SHA3_256 : public HashAlgorithm, private SHA3Base {
public:
    SHA3_256();
    
    std::string name() const override { return "SHA3-256"; }
    size_t output_size() const override { return 32; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

class SHA3_384 : public HashAlgorithm, private SHA3Base {
public:
    SHA3_384();
    
    std::string name() const override { return "SHA3-384"; }
    size_t output_size() const override { return 48; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

class SHA3_512 : public HashAlgorithm, private SHA3Base {
public:
    SHA3_512();
    
    std::string name() const override { return "SHA3-512"; }
    size_t output_size() const override { return 64; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc

#endif // CRYPTOPDC_SHA3_HPP
