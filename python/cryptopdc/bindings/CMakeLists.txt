# Find Python and pybind11
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

# Fetch pybind11 if not found
include(FetchContent)
FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
    GIT_TAG v2.11.1
)
FetchContent_MakeAvailable(pybind11)

# Create Python module
pybind11_add_module(cryptopdc_bindings 
    core_bindings.cpp
)

# Include directories
target_include_directories(cryptopdc_bindings PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
    ${CMAKE_SOURCE_DIR}/cuda/include
)

# Link libraries
target_link_libraries(cryptopdc_bindings PRIVATE 
    cryptopdc_core 
    cryptopdc_cuda
    CUDA::cudart
)

# OpenMP support
if(ENABLE_OPENMP)
    target_link_libraries(cryptopdc_bindings PRIVATE OpenMP::OpenMP_CXX)
endif()

# Output to the python package directory
set_target_properties(cryptopdc_bindings PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/python/cryptopdc/bindings"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    INTERPROCEDURAL_OPTIMIZATION OFF
)

# Custom target to copy the module after build
add_custom_command(TARGET cryptopdc_bindings POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Python bindings built successfully!"
    COMMAND ${CMAKE_COMMAND} -E echo "Module location: ${CMAKE_SOURCE_DIR}/python/cryptopdc/bindings/"
)
