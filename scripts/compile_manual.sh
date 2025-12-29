#!/bin/bash
set -e

echo "Compiling CryptoPDC manually..."

# Create output directories
mkdir -p build/lib
mkdir -p build/obj

# Compiler flags
CXX_FLAGS="-O3 -std=c++17 -fPIC -Icore/include -Icuda/include -fopenmp"
NVCC_FLAGS="-O3 -std=c++17 -Xcompiler -fPIC -Icore/include -Icuda/include"

# Python flags
PY_INCLUDES=$(python3 -m pybind11 --includes)
PY_SUFFIX=$(python3-config --extension-suffix)

# 1. Compile CUDA kernels
echo "Compiling CUDA kernels..."
# nvcc $NVCC_FLAGS -c cuda/src/common.cu -o build/obj/common_cu.o
nvcc $NVCC_FLAGS -c cuda/src/hash/md5_kernel.cu -o build/obj/md5_kernel.o
nvcc $NVCC_FLAGS -c cuda/src/hash/sha1_kernel.cu -o build/obj/sha1_kernel.o
nvcc $NVCC_FLAGS -c cuda/src/hash/sha256_kernel.cu -o build/obj/sha256_kernel.o
nvcc $NVCC_FLAGS -c cuda/src/hash/sha512_kernel.cu -o build/obj/sha512_kernel.o

# AES CUDA kernels
nvcc $NVCC_FLAGS -c cuda/src/symmetric/aes128_kernel.cu -o build/obj/aes128_kernel.o
nvcc $NVCC_FLAGS -c cuda/src/symmetric/aes192_kernel.cu -o build/obj/aes192_kernel.o
nvcc $NVCC_FLAGS -c cuda/src/symmetric/aes256_kernel.cu -o build/obj/aes256_kernel.o

# 2. Compile C++ Core
echo "Compiling C++ Core..."
g++ $CXX_FLAGS -c core/src/common/utils.cpp -o build/obj/utils.o
g++ $CXX_FLAGS -c core/src/common/types.cpp -o build/obj/types.o
g++ $CXX_FLAGS -c core/src/algorithms/hash/md5.cpp -o build/obj/md5.o
g++ $CXX_FLAGS -c core/src/algorithms/hash/sha1.cpp -o build/obj/sha1.o
g++ $CXX_FLAGS -c core/src/algorithms/hash/sha256.cpp -o build/obj/sha256.o
g++ $CXX_FLAGS -c core/src/algorithms/hash/sha512.cpp -o build/obj/sha512.o
g++ $CXX_FLAGS -c core/src/algorithms/symmetric/aes.cpp -o build/obj/aes.o
g++ $CXX_FLAGS -c core/src/cpu_cracker.cpp -o build/obj/cpu_cracker.o

# 3. Compile Python Bindings
echo "Compiling Python Bindings..."
g++ $CXX_FLAGS $PY_INCLUDES -c python/cryptopdc/bindings/core_bindings.cpp -o build/obj/bindings.o

# 4. Link everything into a shared object
echo "Linking..."
g++ -shared -fopenmp -o python/cryptopdc/bindings/cryptopdc_bindings$PY_SUFFIX \
    build/obj/*.o \
    -L/usr/local/cuda/lib64 -lcudart

echo "Build complete! Library is at python/cryptopdc/bindings/cryptopdc_bindings$PY_SUFFIX"
