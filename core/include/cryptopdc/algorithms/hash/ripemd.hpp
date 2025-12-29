#pragma once

#include "cryptopdc/algorithms/algorithm_base.hpp"

namespace cryptopdc {
namespace algorithms {
namespace hash {

class RIPEMD128 : public HashAlgorithm {
public:
    RIPEMD128();
    ~RIPEMD128() override = default;
    
    std::string name() const override { return "RIPEMD-128"; }
    size_t output_size() const override { return 16; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

class RIPEMD160 : public HashAlgorithm {
public:
    RIPEMD160();
    ~RIPEMD160() override = default;
    
    std::string name() const override { return "RIPEMD-160"; }
    size_t output_size() const override { return 20; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

class RIPEMD256 : public HashAlgorithm {
public:
    RIPEMD256();
    ~RIPEMD256() override = default;
    
    std::string name() const override { return "RIPEMD-256"; }
    size_t output_size() const override { return 32; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

class RIPEMD320 : public HashAlgorithm {
public:
    RIPEMD320();
    ~RIPEMD320() override = default;
    
    std::string name() const override { return "RIPEMD-320"; }
    size_t output_size() const override { return 40; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
};

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
