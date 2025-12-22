include(FetchContent)
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG v2.10.1
)
FetchContent_MakeAvailable(pybind11)

pybind11_add_module(cryptopdc_bindings core_bindings.cpp)

target_link_libraries(cryptopdc_bindings PRIVATE cryptopdc_core cryptopdc_cuda)

set_target_properties(cryptopdc_bindings PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/python/cryptopdc/bindings"
)
