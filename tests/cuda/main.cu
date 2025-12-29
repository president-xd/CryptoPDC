#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <iostream>

int main(int argc, char** argv) {
    std::cout << "==================================================" << std::endl;
    std::cout << "     CryptoPDC CUDA Test Suite                    " << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << std::endl;
    
    // Check CUDA device availability
    int deviceCount = 0;
    cudaError_t error = cudaGetDeviceCount(&deviceCount);
    
    if (error != cudaSuccess || deviceCount == 0) {
        std::cout << "WARNING: No CUDA devices available!" << std::endl;
        std::cout << "CUDA tests will be skipped." << std::endl;
    } else {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, 0);
        std::cout << "CUDA Device: " << prop.name << std::endl;
        std::cout << "Compute Capability: " << prop.major << "." << prop.minor << std::endl;
        std::cout << "Total Global Memory: " << (prop.totalGlobalMem / (1024 * 1024)) << " MB" << std::endl;
    }
    std::cout << std::endl;
    
    ::testing::InitGoogleTest(&argc, argv);
    
    // Enable colored output
    ::testing::GTEST_FLAG(color) = "yes";
    
    // Run all tests
    int result = RUN_ALL_TESTS();
    
    std::cout << std::endl;
    std::cout << "==================================================" << std::endl;
    if (result == 0) {
        std::cout << "     All CUDA tests passed!                       " << std::endl;
    } else {
        std::cout << "     Some CUDA tests failed!                      " << std::endl;
    }
    std::cout << "==================================================" << std::endl;
    
    return result;
}
