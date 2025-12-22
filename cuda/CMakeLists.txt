add_library(cryptopdc_cuda
    src/common.cu
    src/hash/md5_kernel.cu
    src/hash/sha256_kernel.cu
)

target_include_directories(cryptopdc_cuda
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(cryptopdc_cuda
    PUBLIC
        CUDA::cudart
)

set_target_properties(cryptopdc_cuda PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    POSITION_INDEPENDENT_CODE ON
)
