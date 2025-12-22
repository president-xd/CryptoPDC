#pragma once

#include "cryptopdc/common/types.hpp"
#include <string>
#include <vector>

namespace cryptopdc {
namespace algorithms {

// Base class for all cryptographic algorithms
class AlgorithmBase {
public:
    virtual ~AlgorithmBase() = default;
    
    // Get algorithm name
    virtual std::string name() const = 0;
    
    // Get algorithm type
    virtual AlgorithmType type() const = 0;
    
    // Get output size in bytes
    virtual size_t output_size() const = 0;
    
    // Check if GPU implementation is available
    virtual bool has_gpu_implementation() const = 0;
};

// Base class for hash algorithms
class HashAlgorithm : public AlgorithmBase {
public:
    AlgorithmType type() const override { return AlgorithmType::HASH; }
    
    // Compute hash of input data
    virtual byte_vector hash(const byte_vector& input) const = 0;
    virtual byte_vector hash(const std::string& input) const = 0;
    
    // Verify if input matches target hash
    virtual bool verify(const std::string& input, const byte_vector& target_hash) const = 0;
};

// Base class for symmetric encryption algorithms
class SymmetricAlgorithm : public AlgorithmBase {
public:
    AlgorithmType type() const override { return AlgorithmType::SYMMETRIC; }
    
    // Encrypt data
    virtual byte_vector encrypt(const byte_vector& plaintext, const byte_vector& key) const = 0;
    
    // Decrypt data
    virtual byte_vector decrypt(const byte_vector& ciphertext, const byte_vector& key) const = 0;
    
    // Verify if key decrypts ciphertext to expected plaintext
    virtual bool verify(const byte_vector& ciphertext, const byte_vector& key, 
                       const byte_vector& expected_plaintext) const = 0;
};

// Base class for asymmetric encryption algorithms
class AsymmetricAlgorithm : public AlgorithmBase {
public:
    AlgorithmType type() const override { return AlgorithmType::ASYMMETRIC; }
    
    // These will be implemented by specific algorithms
    virtual byte_vector encrypt(const byte_vector& plaintext, const byte_vector& public_key) const = 0;
    virtual byte_vector decrypt(const byte_vector& ciphertext, const byte_vector& private_key) const = 0;
};

} // namespace algorithms
} // namespace cryptopdc
