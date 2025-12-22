#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "cryptopdc/algorithms/hash/md5.hpp"
#include "cryptopdc/algorithms/hash/sha1.hpp"
#include "cryptopdc/algorithms/hash/sha256.hpp"
#include "cryptopdc/cuda/hash/md5_kernel.cuh"
#include "cryptopdc/cuda/hash/sha256_kernel.cuh"
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
        
    // Utils
    m.def("bytes_to_hex", [](const std::vector<uint8_t>& data) {
        return utils::bytes_to_hex(data.data(), data.size());
    });
    m.def("hex_to_bytes", &utils::hex_to_bytes);
    m.def("calculate_keyspace_size", &utils::calculate_keyspace_size);
    m.def("key_to_index", [](const std::string& key, const std::string& charset, int key_len) {
        return utils::key_to_index(key.c_str(), charset.c_str(), charset.length(), key_len);
    });
    m.def("index_to_key", [](uint64_t index, const std::string& charset, int key_len) {
        char output[64];
        utils::index_to_key(index, output, charset.c_str(), charset.length(), key_len);
        return std::string(output, key_len);
    });

    // CUDA Crackers
    m.def("cuda_crack_md5", &cuda_crack_md5, 
          py::arg("target"), py::arg("charset"), py::arg("length"), 
          py::arg("start"), py::arg("count"), py::arg("device_id") = 0);
          
    m.def("cuda_crack_sha256", &cuda_crack_sha256, 
          py::arg("target"), py::arg("charset"), py::arg("length"), 
          py::arg("start"), py::arg("count"), py::arg("device_id") = 0);
}
