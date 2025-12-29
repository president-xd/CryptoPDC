#ifndef CRYPTOPDC_SHA384_HPP
#define CRYPTOPDC_SHA384_HPP

#include "cryptopdc/algorithms/algorithm_base.hpp"

namespace cryptopdc {
namespace algorithms {
namespace hash {

class SHA384 : public HashAlgorithm {
public:
    SHA384();
    
    std::string name() const override { return "SHA-384"; }
    size_t output_size() const override { return 48; }  // 384 bits = 48 bytes
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc

#endif // CRYPTOPDC_SHA384_HPP
