#ifndef CRYPTOPDC_MD6_HPP
#define CRYPTOPDC_MD6_HPP

#include "cryptopdc/algorithms/algorithm_base.hpp"

namespace cryptopdc {
namespace algorithms {
namespace hash {

// MD6 base class with shared compression function
class MD6Base {
protected:
    static void md6_compress(uint64_t* C, const uint64_t* N, int r);
    static void md6_hash(const uint8_t* input, size_t length, uint8_t* output, size_t d);
    
    // MD6 constants
    static const uint64_t Q[15];  // 960-bit constant
    static const int S[16];       // Shift amounts
};

class MD6_128 : public HashAlgorithm, private MD6Base {
public:
    MD6_128();
    
    std::string name() const override { return "MD6-128"; }
    size_t output_size() const override { return 16; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

class MD6_256 : public HashAlgorithm, private MD6Base {
public:
    MD6_256();
    
    std::string name() const override { return "MD6-256"; }
    size_t output_size() const override { return 32; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

class MD6_512 : public HashAlgorithm, private MD6Base {
public:
    MD6_512();
    
    std::string name() const override { return "MD6-512"; }
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

#endif // CRYPTOPDC_MD6_HPP
