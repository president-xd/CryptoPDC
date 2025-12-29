#pragma once

#include "cryptopdc/algorithms/algorithm_base.hpp"

namespace cryptopdc {
namespace algorithms {
namespace hash {

class CRC16 : public HashAlgorithm {
public:
    CRC16();
    ~CRC16() override = default;
    
    std::string name() const override { return "CRC16"; }
    size_t output_size() const override { return 2; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
    static uint16_t compute_value(const uint8_t* input, size_t length);
};

class CRC32 : public HashAlgorithm {
public:
    CRC32();
    ~CRC32() override = default;
    
    std::string name() const override { return "CRC32"; }
    size_t output_size() const override { return 4; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
    static uint32_t compute_value(const uint8_t* input, size_t length);
};

class Adler32 : public HashAlgorithm {
public:
    Adler32();
    ~Adler32() override = default;
    
    std::string name() const override { return "Adler32"; }
    size_t output_size() const override { return 4; }
    bool has_gpu_implementation() const override { return true; }
    
    byte_vector hash(const byte_vector& input) const override;
    byte_vector hash(const std::string& input) const override;
    bool verify(const std::string& input, const byte_vector& target_hash) const override;
    
    static void compute(const uint8_t* input, size_t length, uint8_t* output);
    static uint32_t compute_value(const uint8_t* input, size_t length);
};

} // namespace hash
} // namespace algorithms
} // namespace cryptopdc
