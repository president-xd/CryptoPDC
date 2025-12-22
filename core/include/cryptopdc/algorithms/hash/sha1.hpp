#pragma once

#include "cryptopdc/algorithms/algorithm_base.hpp"

namespace cryptopdc {
namespace algorithms {
namespace hash {

class SHA1 : public HashAlgorithm {
public:
    SHA1();
    ~SHA1() override = default;
    
    std::string name() const override { return "SHA-1"; }
    size_t output_size() const override { return 20; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
