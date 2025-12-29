# CUDA kernel sources
set(CUDA_SOURCES
    # Common CUDA utilities
    src/common.cu
    
    # Hash algorithm kernels (GPU implementations)
    src/hash/md5_kernel.cu
    src/hash/sha1_kernel.cu
    src/hash/sha256_kernel.cu
    src/hash/sha512_kernel.cu
    
    # Symmetric encryption kernels (GPU implementations)
    src/symmetric/aes128_kernel.cu
    src/symmetric/aes192_kernel.cu
    src/symmetric/aes256_kernel.cu
)

add_library(cryptopdc_cuda ${CUDA_SOURCES})

target_include_directories(cryptopdc_cuda
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/core/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(cryptopdc_cuda
    PUBLIC
        CUDA::cudart
)

set_target_properties(cryptopdc_cuda PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    POSITION_INDEPENDENT_CODE ON
    CUDA_STANDARD 14
    CUDA_STANDARD_REQUIRED ON
)

# Installation
install(TARGETS cryptopdc_cuda
    EXPORT CryptoPDCTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/cryptopdc
    DESTINATION include
)
