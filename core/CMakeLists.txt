add_library(cryptopdc_core
    src/common/utils.cpp
    src/common/types.cpp
    src/algorithms/hash/md5.cpp
    src/algorithms/hash/sha256.cpp
)

target_include_directories(cryptopdc_core
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(cryptopdc_core
    PUBLIC
        cryptopdc_cuda
)

if(ENABLE_OPENMP)
    target_link_libraries(cryptopdc_core PUBLIC OpenMP::OpenMP_CXX)
endif()
