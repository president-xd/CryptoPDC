#ifndef CRYPTOPDC_TEST_CUDA_UTILS_CUH
#define CRYPTOPDC_TEST_CUDA_UTILS_CUH

#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

namespace cryptopdc {
namespace test {
namespace cuda {

// Convert byte array to hex string for comparison
inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

// Check if CUDA device is available
inline bool cuda_available() {
    int deviceCount = 0;
    cudaError_t error = cudaGetDeviceCount(&deviceCount);
    return error == cudaSuccess && deviceCount > 0;
}

// Base test fixture for CUDA hash kernel tests
class CudaHashKernelTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!cuda_available()) {
            GTEST_SKIP() << "CUDA device not available";
        }
    }
};

// Base test fixture for CUDA symmetric kernel tests  
class CudaSymmetricKernelTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!cuda_available()) {
            GTEST_SKIP() << "CUDA device not available";
        }
    }
};

} // namespace cuda
} // namespace test
} // namespace cryptopdc

#endif // CRYPTOPDC_TEST_CUDA_UTILS_CUH
