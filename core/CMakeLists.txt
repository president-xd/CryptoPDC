# Core library sources
set(CORE_SOURCES
    # Common utilities
    src/common/utils.cpp
    src/common/types.cpp
    
    # Hash algorithms (CPU implementations)
    src/algorithms/hash/md2.cpp
    src/algorithms/hash/md4.cpp
    src/algorithms/hash/md5.cpp
    src/algorithms/hash/md6.cpp
    src/algorithms/hash/ntlm.cpp
    src/algorithms/hash/sha1.cpp
    src/algorithms/hash/sha224.cpp
    src/algorithms/hash/sha256.cpp
    src/algorithms/hash/sha384.cpp
    src/algorithms/hash/sha512.cpp
    src/algorithms/hash/sha3.cpp
    src/algorithms/hash/ripemd.cpp
    src/algorithms/hash/checksum.cpp
    src/algorithms/hash/whirlpool.cpp
    
    # Symmetric encryption (CPU implementations)
    src/algorithms/symmetric/aes.cpp
    
    # CPU Cracker
    src/cpu_cracker.cpp
)

add_library(cryptopdc_core ${CORE_SOURCES})

target_include_directories(cryptopdc_core
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Link with CUDA library
target_link_libraries(cryptopdc_core
    PUBLIC
        cryptopdc_cuda
)

# OpenMP support for CPU parallelization
if(ENABLE_OPENMP)
    target_link_libraries(cryptopdc_core PUBLIC OpenMP::OpenMP_CXX)
endif()

# Set properties
set_target_properties(cryptopdc_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Installation
install(TARGETS cryptopdc_core
    EXPORT CryptoPDCTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/cryptopdc
    DESTINATION include
)
