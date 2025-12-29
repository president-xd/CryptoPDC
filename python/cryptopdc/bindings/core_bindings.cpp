#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "cryptopdc/algorithms/hash/md5.hpp"
#include "cryptopdc/algorithms/hash/sha1.hpp"
#include "cryptopdc/algorithms/hash/sha256.hpp"
#include "cryptopdc/algorithms/hash/sha512.hpp"
#include "cryptopdc/algorithms/symmetric/aes.hpp"
#include "cryptopdc/cpu_cracker.hpp"
#include "cryptopdc/cuda/hash/md5_kernel.cuh"
#include "cryptopdc/cuda/hash/sha1_kernel.cuh"
#include "cryptopdc/cuda/hash/sha256_kernel.cuh"
#include "cryptopdc/cuda/hash/sha512_kernel.cuh"
#include "cryptopdc/cuda/symmetric/aes128_kernel.cuh"
#include "cryptopdc/cuda/symmetric/aes192_kernel.cuh"
#include "cryptopdc/cuda/symmetric/aes256_kernel.cuh"
#include "cryptopdc/common/types.hpp"
#include "cryptopdc/common/utils.hpp"

namespace py = pybind11;
using namespace cryptopdc;

// Helper to launch MD5 CUDA crack
std::pair<bool, std::string> cuda_crack_md5(const std::string& target_hash_hex, 
                                          const std::string& charset,
                                          int key_length,
                                          uint64_t start_index,
                                          uint64_t count,
                                          int device_id) {
    auto target_bytes = utils::hex_to_bytes(target_hash_hex);
    if (target_bytes.size() != 16) {
        throw std::runtime_error("Invalid MD5 hash length");
    }

    char result_key[64];
    int found = 0;
    
    // In a real app, you might want to handle CUDA errors gracefully here
    // For now we rely on the CUDA_CHECK macro in the kernel launcher to print/exit or we could change it to throw
    
    cudaError_t err = cuda::hash::launch_md5_crack(
        target_bytes.data(),
        start_index,
        count,
        charset.c_str(),
        charset.length(),
        key_length,
        result_key,
        &found,
        device_id
    );

    if (err != cudaSuccess) {
        throw std::runtime_error("CUDA execution failed");
    }

    if (found) {
        return {true, std::string(result_key, key_length)};
    }
    return {false, ""};
}

// Helper to launch SHA-256 CUDA crack
std::pair<bool, std::string> cuda_crack_sha256(const std::string& target_hash_hex, 
                                             const std::string& charset,
                                             int key_length,
                                             uint64_t start_index,
                                             uint64_t count,
                                             int device_id) {
    auto target_bytes = utils::hex_to_bytes(target_hash_hex);
    if (target_bytes.size() != 32) {
        throw std::runtime_error("Invalid SHA-256 hash length");
    }

    char result_key[64];
    int found = 0;
    
    cudaError_t err = cuda::hash::launch_sha256_crack(
        target_bytes.data(),
        start_index,
        count,
        charset.c_str(),
        charset.length(),
        key_length,
        result_key,
        &found,
        device_id
    );

    if (err != cudaSuccess) {
        throw std::runtime_error("CUDA execution failed");
    }

    if (found) {
        return {true, std::string(result_key, key_length)};
    }
    return {false, ""};
}

// Helper to launch SHA-1 CUDA crack
std::pair<bool, std::string> cuda_crack_sha1(const std::string& target_hash_hex, 
                                            const std::string& charset,
                                            int key_length,
                                            uint64_t start_index,
                                            uint64_t count,
                                            int device_id) {
    auto target_bytes = utils::hex_to_bytes(target_hash_hex);
    if (target_bytes.size() != 20) {
        throw std::runtime_error("Invalid SHA-1 hash length (expected 40 hex characters / 20 bytes)");
    }

    char result_key[64];
    int found = 0;
    
    cudaError_t err = cuda::hash::launch_sha1_crack(
        target_bytes.data(),
        start_index,
        count,
        charset.c_str(),
        charset.length(),
        key_length,
        result_key,
        &found,
        device_id
    );

    if (err != cudaSuccess) {
        throw std::runtime_error("CUDA execution failed");
    }

    if (found) {
        return {true, std::string(result_key, key_length)};
    }
    return {false, ""};
}

// Helper to launch SHA-512 CUDA crack
std::pair<bool, std::string> cuda_crack_sha512(const std::string& target_hash_hex, 
                                              const std::string& charset,
                                              int key_length,
                                              uint64_t start_index,
                                              uint64_t count,
                                              int device_id) {
    auto target_bytes = utils::hex_to_bytes(target_hash_hex);
    if (target_bytes.size() != 64) {
        throw std::runtime_error("Invalid SHA-512 hash length (expected 128 hex characters / 64 bytes)");
    }

    char result_key[64];
    int found = 0;
    
    cudaError_t err = cuda::hash::launch_sha512_crack(
        target_bytes.data(),
        start_index,
        count,
        charset.c_str(),
        charset.length(),
        key_length,
        result_key,
        &found,
        device_id
    );

    if (err != cudaSuccess) {
        throw std::runtime_error("CUDA execution failed");
    }

    if (found) {
        return {true, std::string(result_key, key_length)};
    }
    return {false, ""};
}

// Helper to launch AES-128 CUDA crack
std::string cuda_crack_aes128_wrapper(const std::string& plaintext_hex,
                                      const std::string& ciphertext_hex,
                                      const std::vector<std::string>& candidates) {
    auto plaintext_bytes = utils::hex_to_bytes(plaintext_hex);
    auto ciphertext_bytes = utils::hex_to_bytes(ciphertext_hex);
    
    if (plaintext_bytes.size() != 16) {
        throw std::runtime_error("Invalid plaintext length (expected 32 hex characters / 16 bytes)");
    }
    if (ciphertext_bytes.size() != 16) {
        throw std::runtime_error("Invalid ciphertext length (expected 32 hex characters / 16 bytes)");
    }
    
    return cuda::cuda_crack_aes128(plaintext_bytes.data(), ciphertext_bytes.data(), candidates);
}

// Helper to launch AES-192 CUDA crack
std::string cuda_crack_aes192_wrapper(const std::string& plaintext_hex,
                                      const std::string& ciphertext_hex,
                                      const std::vector<std::string>& candidates) {
    auto plaintext_bytes = utils::hex_to_bytes(plaintext_hex);
    auto ciphertext_bytes = utils::hex_to_bytes(ciphertext_hex);
    
    if (plaintext_bytes.size() != 16) {
        throw std::runtime_error("Invalid plaintext length (expected 32 hex characters / 16 bytes)");
    }
    if (ciphertext_bytes.size() != 16) {
        throw std::runtime_error("Invalid ciphertext length (expected 32 hex characters / 16 bytes)");
    }
    
    return cuda::cuda_crack_aes192(plaintext_bytes.data(), ciphertext_bytes.data(), candidates);
}

// Helper to launch AES-256 CUDA crack
std::string cuda_crack_aes256_wrapper(const std::string& plaintext_hex,
                                      const std::string& ciphertext_hex,
                                      const std::vector<std::string>& candidates) {
    auto plaintext_bytes = utils::hex_to_bytes(plaintext_hex);
    auto ciphertext_bytes = utils::hex_to_bytes(ciphertext_hex);
    
    if (plaintext_bytes.size() != 16) {
        throw std::runtime_error("Invalid plaintext length (expected 32 hex characters / 16 bytes)");
    }
    if (ciphertext_bytes.size() != 16) {
        throw std::runtime_error("Invalid ciphertext length (expected 32 hex characters / 16 bytes)");
    }
    
    return cuda::cuda_crack_aes256(plaintext_bytes.data(), ciphertext_bytes.data(), candidates);
}

PYBIND11_MODULE(cryptopdc_bindings, m) {
    m.doc() = "CryptoPDC Core C++ Bindings";

    // Hash Algorithms
    py::class_<algorithms::hash::MD5>(m, "MD5")
        .def(py::init<>())
        .def("hash", (std::vector<uint8_t> (algorithms::hash::MD5::*)(const std::string&) const) &algorithms::hash::MD5::hash)
        .def("verify", &algorithms::hash::MD5::verify);

    py::class_<algorithms::hash::SHA1>(m, "SHA1")
        .def(py::init<>())
        .def("hash", (std::vector<uint8_t> (algorithms::hash::SHA1::*)(const std::string&) const) &algorithms::hash::SHA1::hash)
        .def("verify", &algorithms::hash::SHA1::verify);

    py::class_<algorithms::hash::SHA256>(m, "SHA256")
        .def(py::init<>())
        .def("hash", (std::vector<uint8_t> (algorithms::hash::SHA256::*)(const std::string&) const) &algorithms::hash::SHA256::hash)
        .def("verify", &algorithms::hash::SHA256::verify);

    py::class_<algorithms::hash::SHA512>(m, "SHA512")
        .def(py::init<>())
        .def("hash", (std::vector<uint8_t> (algorithms::hash::SHA512::*)(const std::string&) const) &algorithms::hash::SHA512::hash)
        .def("verify", &algorithms::hash::SHA512::verify);
        
    // Utils - Hex encoding
    m.def("bytes_to_hex", [](const std::vector<uint8_t>& data) {
        return utils::bytes_to_hex(data.data(), data.size());
    }, "Convert bytes to hex string");
    m.def("hex_to_bytes", &utils::hex_to_bytes, "Convert hex string to bytes");
    m.def("is_valid_hex", &utils::is_valid_hex, "Check if string is valid hex");
    
    // Utils - Base64 encoding
    m.def("bytes_to_base64", [](const std::vector<uint8_t>& data) {
        return utils::bytes_to_base64(data);
    }, "Convert bytes to base64 string");
    m.def("base64_to_bytes", &utils::base64_to_bytes, "Convert base64 string to bytes");
    m.def("is_valid_base64", &utils::is_valid_base64, "Check if string is valid base64");
    
    // Utils - Format conversion
    m.def("hex_to_base64", &utils::hex_to_base64, "Convert hex string to base64");
    m.def("base64_to_hex", &utils::base64_to_hex, "Convert base64 string to hex");
    
    // Utils - Keyspace
    m.def("calculate_keyspace_size", &utils::calculate_keyspace_size);
    m.def("key_to_index", [](const std::string& key, const std::string& charset, int key_len) {
        return utils::key_to_index(key.c_str(), charset.c_str(), charset.length(), key_len);
    });
    m.def("index_to_key", [](uint64_t index, const std::string& charset, int key_len) {
        char output[64];
        utils::index_to_key(index, output, charset.c_str(), charset.length(), key_len);
        return std::string(output, key_len);
    });

    // CPU Crackers
    m.def("crack_dictionary", [](const std::string& algo, const std::string& target, const std::string& wordlist) {
        auto result = cpu::CPUCracker::crack_dictionary(algo, target, wordlist);
        return std::make_tuple(result.found, result.key, result.iterations);
    });

    m.def("crack_brute_force_cpu", [](const std::string& algo, const std::string& target, const std::string& charset, int min_len, int max_len) {
        auto result = cpu::CPUCracker::crack_brute_force(algo, target, charset, min_len, max_len);
        return std::make_tuple(result.found, result.key, result.iterations);
    });

    // CUDA Crackers
    m.def("cuda_crack_md5", &cuda_crack_md5, 
          py::arg("target"), py::arg("charset"), py::arg("length"), 
          py::arg("start"), py::arg("count"), py::arg("device_id") = 0);
    
    m.def("cuda_crack_sha1", &cuda_crack_sha1, 
          py::arg("target"), py::arg("charset"), py::arg("length"), 
          py::arg("start"), py::arg("count"), py::arg("device_id") = 0);
          
    m.def("cuda_crack_sha256", &cuda_crack_sha256, 
          py::arg("target"), py::arg("charset"), py::arg("length"), 
          py::arg("start"), py::arg("count"), py::arg("device_id") = 0);
    
    m.def("cuda_crack_sha512", &cuda_crack_sha512, 
          py::arg("target"), py::arg("charset"), py::arg("length"), 
          py::arg("start"), py::arg("count"), py::arg("device_id") = 0);
    
    // CUDA AES Crackers
    m.def("cuda_crack_aes128", &cuda_crack_aes128_wrapper,
          py::arg("plaintext_hex"), py::arg("ciphertext_hex"), py::arg("candidates"),
          "Crack AES-128 key given plaintext, ciphertext and candidate keys");
    
    m.def("cuda_crack_aes192", &cuda_crack_aes192_wrapper,
          py::arg("plaintext_hex"), py::arg("ciphertext_hex"), py::arg("candidates"),
          "Crack AES-192 key given plaintext, ciphertext and candidate keys");
    
    m.def("cuda_crack_aes256", &cuda_crack_aes256_wrapper,
          py::arg("plaintext_hex"), py::arg("ciphertext_hex"), py::arg("candidates"),
          "Crack AES-256 key given plaintext, ciphertext and candidate keys");
    
    // CUDA availability checks
    m.def("cuda_aes128_available", &cuda::cuda_aes128_available);
    m.def("cuda_aes192_available", &cuda::cuda_aes192_available);
    m.def("cuda_aes256_available", &cuda::cuda_aes256_available);
    
    // AES CPU classes with hex and base64 support
    py::class_<algorithms::symmetric::AES128>(m, "AES128")
        .def(py::init<>())
        .def_static("encrypt", [](const std::string& plaintext_hex, const std::string& key_hex) {
            auto plaintext = utils::hex_to_bytes(plaintext_hex);
            auto key = utils::hex_to_bytes(key_hex);
            if (plaintext.size() != 16) throw std::runtime_error("Plaintext must be 16 bytes");
            if (key.size() != 16) throw std::runtime_error("Key must be 16 bytes for AES-128");
            uint8_t ciphertext[16];
            algorithms::symmetric::AES128::compute_encrypt(plaintext.data(), key.data(), ciphertext);
            return utils::bytes_to_hex(ciphertext, 16);
        }, "Encrypt with hex input/output")
        .def_static("encrypt_base64", [](const std::string& plaintext_b64, const std::string& key_b64) {
            auto plaintext = utils::base64_to_bytes(plaintext_b64);
            auto key = utils::base64_to_bytes(key_b64);
            if (plaintext.size() != 16) throw std::runtime_error("Plaintext must be 16 bytes");
            if (key.size() != 16) throw std::runtime_error("Key must be 16 bytes for AES-128");
            uint8_t ciphertext[16];
            algorithms::symmetric::AES128::compute_encrypt(plaintext.data(), key.data(), ciphertext);
            return utils::bytes_to_base64(ciphertext, 16);
        }, "Encrypt with base64 input/output")
        .def_static("encrypt_hex_to_base64", [](const std::string& plaintext_hex, const std::string& key_hex) {
            auto plaintext = utils::hex_to_bytes(plaintext_hex);
            auto key = utils::hex_to_bytes(key_hex);
            if (plaintext.size() != 16) throw std::runtime_error("Plaintext must be 16 bytes");
            if (key.size() != 16) throw std::runtime_error("Key must be 16 bytes for AES-128");
            uint8_t ciphertext[16];
            algorithms::symmetric::AES128::compute_encrypt(plaintext.data(), key.data(), ciphertext);
            return utils::bytes_to_base64(ciphertext, 16);
        }, "Encrypt hex input, output base64");
    
    py::class_<algorithms::symmetric::AES192>(m, "AES192")
        .def(py::init<>())
        .def_static("encrypt", [](const std::string& plaintext_hex, const std::string& key_hex) {
            auto plaintext = utils::hex_to_bytes(plaintext_hex);
            auto key = utils::hex_to_bytes(key_hex);
            if (plaintext.size() != 16) throw std::runtime_error("Plaintext must be 16 bytes");
            if (key.size() != 24) throw std::runtime_error("Key must be 24 bytes for AES-192");
            uint8_t ciphertext[16];
            algorithms::symmetric::AES192::compute_encrypt(plaintext.data(), key.data(), ciphertext);
            return utils::bytes_to_hex(ciphertext, 16);
        }, "Encrypt with hex input/output")
        .def_static("encrypt_base64", [](const std::string& plaintext_b64, const std::string& key_b64) {
            auto plaintext = utils::base64_to_bytes(plaintext_b64);
            auto key = utils::base64_to_bytes(key_b64);
            if (plaintext.size() != 16) throw std::runtime_error("Plaintext must be 16 bytes");
            if (key.size() != 24) throw std::runtime_error("Key must be 24 bytes for AES-192");
            uint8_t ciphertext[16];
            algorithms::symmetric::AES192::compute_encrypt(plaintext.data(), key.data(), ciphertext);
            return utils::bytes_to_base64(ciphertext, 16);
        }, "Encrypt with base64 input/output")
        .def_static("encrypt_hex_to_base64", [](const std::string& plaintext_hex, const std::string& key_hex) {
            auto plaintext = utils::hex_to_bytes(plaintext_hex);
            auto key = utils::hex_to_bytes(key_hex);
            if (plaintext.size() != 16) throw std::runtime_error("Plaintext must be 16 bytes");
            if (key.size() != 24) throw std::runtime_error("Key must be 24 bytes for AES-192");
            uint8_t ciphertext[16];
            algorithms::symmetric::AES192::compute_encrypt(plaintext.data(), key.data(), ciphertext);
            return utils::bytes_to_base64(ciphertext, 16);
        }, "Encrypt hex input, output base64");
    
    py::class_<algorithms::symmetric::AES256>(m, "AES256")
        .def(py::init<>())
        .def_static("encrypt", [](const std::string& plaintext_hex, const std::string& key_hex) {
            auto plaintext = utils::hex_to_bytes(plaintext_hex);
            auto key = utils::hex_to_bytes(key_hex);
            if (plaintext.size() != 16) throw std::runtime_error("Plaintext must be 16 bytes");
            if (key.size() != 32) throw std::runtime_error("Key must be 32 bytes for AES-256");
            uint8_t ciphertext[16];
            algorithms::symmetric::AES256::compute_encrypt(plaintext.data(), key.data(), ciphertext);
            return utils::bytes_to_hex(ciphertext, 16);
        }, "Encrypt with hex input/output")
        .def_static("encrypt_base64", [](const std::string& plaintext_b64, const std::string& key_b64) {
            auto plaintext = utils::base64_to_bytes(plaintext_b64);
            auto key = utils::base64_to_bytes(key_b64);
            if (plaintext.size() != 16) throw std::runtime_error("Plaintext must be 16 bytes");
            if (key.size() != 32) throw std::runtime_error("Key must be 32 bytes for AES-256");
            uint8_t ciphertext[16];
            algorithms::symmetric::AES256::compute_encrypt(plaintext.data(), key.data(), ciphertext);
            return utils::bytes_to_base64(ciphertext, 16);
        }, "Encrypt with base64 input/output")
        .def_static("encrypt_hex_to_base64", [](const std::string& plaintext_hex, const std::string& key_hex) {
            auto plaintext = utils::hex_to_bytes(plaintext_hex);
            auto key = utils::hex_to_bytes(key_hex);
            if (plaintext.size() != 16) throw std::runtime_error("Plaintext must be 16 bytes");
            if (key.size() != 32) throw std::runtime_error("Key must be 32 bytes for AES-256");
            uint8_t ciphertext[16];
            algorithms::symmetric::AES256::compute_encrypt(plaintext.data(), key.data(), ciphertext);
            return utils::bytes_to_base64(ciphertext, 16);
        }, "Encrypt hex input, output base64");
}
