#ifndef CRYPTOPDC_SHA224_HPP
#define CRYPTOPDC_SHA224_HPP

#include "cryptopdc/algorithms/hash_algorithm.hpp"

namespace cryptopdc {
namespace algorithms {
namespace hash {

class SHA224 : public HashAlgorithm {
public:
    SHA224();
    
    std::string name() const override { return "SHA-224"; }
    size_t output_size() const override { return 28; }  // 224 bits = 28 bytes
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc

#endif // CRYPTOPDC_SHA224_HPP
