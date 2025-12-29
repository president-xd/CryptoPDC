#ifndef CRYPTOPDC_WHIRLPOOL_HPP
#define CRYPTOPDC_WHIRLPOOL_HPP

#include "cryptopdc/algorithms/algorithm_base.hpp"

namespace cryptopdc {
namespace algorithms {
namespace hash {

class Whirlpool : public HashAlgorithm {
public:
    Whirlpool();
    
    std::string name() const override { return "Whirlpool"; }
    size_t output_size() const override { return 64; }  // 512 bits
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
    
private:
    static void whirlpool_transform(uint64_t* hash, const uint8_t* block);
};

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc

#endif // CRYPTOPDC_WHIRLPOOL_HPP
