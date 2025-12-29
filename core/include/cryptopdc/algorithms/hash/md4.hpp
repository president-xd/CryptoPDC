#pragma once

#include "cryptopdc/algorithms/algorithm_base.hpp"

namespace cryptopdc {
namespace algorithms {
namespace hash {

class MD4 : public HashAlgorithm {
public:
    MD4();
    ~MD4() override = default;
    
    std::string name() const override { return "MD4"; }
    size_t output_size() const override { return 16; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    // Static method for direct hashing
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
