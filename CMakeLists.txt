cmake_minimum_required(VERSION 3.18)
project(CryptoPDC VERSION 1.0.0 LANGUAGES CXX CUDA)

# Project metadata
set(PROJECT_DESCRIPTION "Professional Distributed Cryptanalysis Framework")
set(PROJECT_HOMEPAGE_URL "https://github.com/cryptopdc/cryptopdc")

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# CUDA Standard
set(CMAKE_CUDA_STANDARD 14)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")

# CUDA flags
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xcompiler -Wall")
set(CMAKE_CUDA_FLAGS_RELEASE "-O3 -use_fast_math -DNDEBUG")

# CUDA architectures (adjust based on your GPU)
set(CMAKE_CUDA_ARCHITECTURES 60 61 70 75 80 86)

# Options
option(BUILD_TESTING "Build tests" ON)
option(BUILD_BENCHMARKS "Build benchmarks" ON)
option(BUILD_PYTHON_BINDINGS "Build Python bindings" ON)
option(ENABLE_OPENMP "Enable OpenMP for CPU parallelization" ON)

# Find packages
find_package(Threads REQUIRED)
find_package(CUDAToolkit REQUIRED)

if(ENABLE_OPENMP)
    find_package(OpenMP REQUIRED)
endif()

if(BUILD_PYTHON_BINDINGS)
    find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
    # pybind11 will be added as subdirectory or found
endif()

if(BUILD_TESTING)
    enable_testing()
    # Google Test will be fetched
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
    )
    FetchContent_MakeAvailable(googletest)
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/core/include
    ${CMAKE_SOURCE_DIR}/cuda/include
)

# Subdirectories
add_subdirectory(core)
add_subdirectory(cuda)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

if(BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

if(BUILD_PYTHON_BINDINGS)
    add_subdirectory(python/cryptopdc/bindings)
endif()

# Installation
install(DIRECTORY core/include/cryptopdc DESTINATION include)
install(DIRECTORY cuda/include/cryptopdc DESTINATION include)

# Package configuration
include(CMakePackageConfigHelper)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/CryptoPDCConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

# Summary
message(STATUS "")
message(STATUS "CryptoPDC Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "  CUDA Compiler: ${CMAKE_CUDA_COMPILER}")
message(STATUS "  CUDA Architectures: ${CMAKE_CUDA_ARCHITECTURES}")
message(STATUS "  OpenMP: ${ENABLE_OPENMP}")
message(STATUS "  Build tests: ${BUILD_TESTING}")
message(STATUS "  Build benchmarks: ${BUILD_BENCHMARKS}")
message(STATUS "  Build Python bindings: ${BUILD_PYTHON_BINDINGS}")
message(STATUS "")
