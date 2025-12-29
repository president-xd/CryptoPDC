# CryptoPDC Test Suite
cmake_minimum_required(VERSION 3.18)

# Find or fetch Google Test
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

enable_testing()

# =============================================================================
# Hash Algorithm Tests (CPU)
# =============================================================================
add_executable(test_hash_algorithms
    cpp/main.cpp
    cpp/test_md2.cpp
    cpp/test_md4.cpp
    cpp/test_md5.cpp
    cpp/test_md6.cpp
    cpp/test_ntlm.cpp
    cpp/test_sha1.cpp
    cpp/test_sha224.cpp
    cpp/test_sha256.cpp
    cpp/test_sha384.cpp
    cpp/test_sha512.cpp
    cpp/test_sha3.cpp
    cpp/test_ripemd.cpp
    cpp/test_checksum.cpp
    cpp/test_whirlpool.cpp
)

target_link_libraries(test_hash_algorithms
    PRIVATE
        cryptopdc_core
        gtest
)

target_include_directories(test_hash_algorithms
    PRIVATE
        ${CMAKE_SOURCE_DIR}/core/include
        ${CMAKE_CURRENT_SOURCE_DIR}/cpp
)

set_target_properties(test_hash_algorithms PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# =============================================================================
# CPU Cracker Tests
# =============================================================================
add_executable(test_cpu_cracker
    cpp/test_cpu_cracker.cpp
)

target_link_libraries(test_cpu_cracker
    PRIVATE
        cryptopdc_core
        gtest_main
)

target_include_directories(test_cpu_cracker
    PRIVATE
        ${CMAKE_SOURCE_DIR}/core/include
        ${CMAKE_CURRENT_SOURCE_DIR}/cpp
)

set_target_properties(test_cpu_cracker PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# =============================================================================
# CUDA Kernel Tests
# =============================================================================
if(CMAKE_CUDA_COMPILER)
    # CUDA Hash Kernel Tests
    add_executable(test_cuda_hash_kernels
        cuda/main.cu
        cuda/test_cuda_md5.cu
        cuda/test_cuda_sha1.cu
        cuda/test_cuda_sha256.cu
        cuda/test_cuda_sha512.cu
    )
    
    target_link_libraries(test_cuda_hash_kernels
        PRIVATE
            cryptopdc_cuda
            cryptopdc_core
            gtest
            CUDA::cudart
    )
    
    target_include_directories(test_cuda_hash_kernels
        PRIVATE
            ${CMAKE_SOURCE_DIR}/core/include
            ${CMAKE_SOURCE_DIR}/cuda/include
            ${CMAKE_CURRENT_SOURCE_DIR}/cuda
    )
    
    set_target_properties(test_cuda_hash_kernels PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON
        CUDA_STANDARD 14
        CXX_STANDARD 17
    )
    
    # CUDA Symmetric Kernel Tests
    add_executable(test_cuda_symmetric_kernels
        cuda/main.cu
        cuda/test_cuda_aes128.cu
        cuda/test_cuda_aes192.cu
        cuda/test_cuda_aes256.cu
    )
    
    target_link_libraries(test_cuda_symmetric_kernels
        PRIVATE
            cryptopdc_cuda
            cryptopdc_core
            gtest
            CUDA::cudart
    )
    
    target_include_directories(test_cuda_symmetric_kernels
        PRIVATE
            ${CMAKE_SOURCE_DIR}/core/include
            ${CMAKE_SOURCE_DIR}/cuda/include
            ${CMAKE_CURRENT_SOURCE_DIR}/cuda
    )
    
    set_target_properties(test_cuda_symmetric_kernels PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON
        CUDA_STANDARD 14
        CXX_STANDARD 17
    )
    
    add_test(NAME CUDAHashKernelTests COMMAND test_cuda_hash_kernels)
    add_test(NAME CUDASymmetricKernelTests COMMAND test_cuda_symmetric_kernels)
endif()

# =============================================================================
# Register Tests with CTest
# =============================================================================
add_test(NAME HashAlgorithmTests COMMAND test_hash_algorithms)
add_test(NAME CPUCrackerTests COMMAND test_cpu_cracker)

# Add test discovery for CTest
include(GoogleTest)
gtest_discover_tests(test_hash_algorithms)
gtest_discover_tests(test_cpu_cracker)

if(CMAKE_CUDA_COMPILER)
    gtest_discover_tests(test_cuda_hash_kernels)
    gtest_discover_tests(test_cuda_symmetric_kernels)
endif()

# =============================================================================
# Custom Test Targets
# =============================================================================
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test_hash_algorithms test_cpu_cracker
    COMMENT "Running all CPU tests"
)

if(CMAKE_CUDA_COMPILER)
    add_custom_target(run_cuda_tests
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -R CUDA
        DEPENDS test_cuda_hash_kernels test_cuda_symmetric_kernels
        COMMENT "Running all CUDA tests"
    )
    
    add_custom_target(run_all_tests
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        DEPENDS test_hash_algorithms test_cpu_cracker test_cuda_hash_kernels test_cuda_symmetric_kernels
        COMMENT "Running all tests (CPU + CUDA)"
    )
endif()
