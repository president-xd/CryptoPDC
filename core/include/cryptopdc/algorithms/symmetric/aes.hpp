#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace cryptopdc {
namespace algorithms {
namespace symmetric {

// AES S-box
extern const uint8_t AES_SBOX[256];

// AES inverse S-box
extern const uint8_t AES_INV_SBOX[256];

// AES round constants
extern const uint8_t AES_RCON[11];

// Base AES class
class AESBase {
public:
    virtual ~AESBase() = default;
    
    virtual std::string name() const = 0;
    virtual size_t key_size() const = 0;  // in bytes
    virtual size_t num_rounds() const = 0;
    virtual bool has_gpu_implementation() const { return true; }
    
    // Encrypt a single 16-byte block
    virtual void encrypt_block(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext) const = 0;
    
    // Decrypt a single 16-byte block
    virtual void decrypt_block(const uint8_t* ciphertext, const uint8_t* key, uint8_t* plaintext) const = 0;
    
    // Verify if a key produces expected ciphertext from known plaintext
    virtual bool verify_key(const uint8_t* key, const uint8_t* plaintext, const uint8_t* expected_ciphertext) const;
    
protected:
    // Key expansion
    void key_expansion(const uint8_t* key, uint8_t* round_keys, int key_size, int num_rounds) const;
    
    // AES round functions
    void sub_bytes(uint8_t* state) const;
    void inv_sub_bytes(uint8_t* state) const;
    void shift_rows(uint8_t* state) const;
    void inv_shift_rows(uint8_t* state) const;
    void mix_columns(uint8_t* state) const;
    void inv_mix_columns(uint8_t* state) const;
    void add_round_key(uint8_t* state, const uint8_t* round_key) const;
    
    // Galois field multiplication
    uint8_t gf_mul(uint8_t a, uint8_t b) const;
};

// AES-128 (128-bit key, 10 rounds)
class AES128 : public AESBase {
public:
    AES128() = default;
    ~AES128() override = default;
    
    std::string name() const override { return "AES-128"; }
    size_t key_size() const override { return 16; }  // 128 bits = 16 bytes
    size_t num_rounds() const override { return 10; }
    
    void encrypt_block(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, const uint8_t* key, uint8_t* plaintext) const override;
    
    // Static compute function for cracking
    static void compute_encrypt(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext);
};

// AES-192 (192-bit key, 12 rounds)
class AES192 : public AESBase {
public:
    AES192() = default;
    ~AES192() override = default;
    
    std::string name() const override { return "AES-192"; }
    size_t key_size() const override { return 24; }  // 192 bits = 24 bytes
    size_t num_rounds() const override { return 12; }
    
    void encrypt_block(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, const uint8_t* key, uint8_t* plaintext) const override;
    
    static void compute_encrypt(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext);
};

// AES-256 (256-bit key, 14 rounds)
class AES256 : public AESBase {
public:
    AES256() = default;
    ~AES256() override = default;
    
    std::string name() const override { return "AES-256"; }
    size_t key_size() const override { return 32; }  // 256 bits = 32 bytes
    size_t num_rounds() const override { return 14; }
    
    void encrypt_block(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, const uint8_t* key, uint8_t* plaintext) const override;
    
    static void compute_encrypt(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext);
};

} // namespace symmetric
} // namespace algorithms
} // namespace cryptopdc
