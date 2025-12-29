# CMake generated Testfile for 
# Source directory: /home/president/CryptoPDC/tests
# Build directory: /home/president/CryptoPDC/build/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
include("/home/president/CryptoPDC/build/tests/test_hash_algorithms[1]_include.cmake")
include("/home/president/CryptoPDC/build/tests/test_cpu_cracker[1]_include.cmake")
include("/home/president/CryptoPDC/build/tests/test_cuda_hash_kernels[1]_include.cmake")
include("/home/president/CryptoPDC/build/tests/test_cuda_symmetric_kernels[1]_include.cmake")
add_test(CUDAHashKernelTests "/home/president/CryptoPDC/build/tests/test_cuda_hash_kernels")
set_tests_properties(CUDAHashKernelTests PROPERTIES  _BACKTRACE_TRIPLES "/home/president/CryptoPDC/tests/CMakeLists.txt;140;add_test;/home/president/CryptoPDC/tests/CMakeLists.txt;0;")
add_test(CUDASymmetricKernelTests "/home/president/CryptoPDC/build/tests/test_cuda_symmetric_kernels")
set_tests_properties(CUDASymmetricKernelTests PROPERTIES  _BACKTRACE_TRIPLES "/home/president/CryptoPDC/tests/CMakeLists.txt;141;add_test;/home/president/CryptoPDC/tests/CMakeLists.txt;0;")
add_test(HashAlgorithmTests "/home/president/CryptoPDC/build/tests/test_hash_algorithms")
set_tests_properties(HashAlgorithmTests PROPERTIES  _BACKTRACE_TRIPLES "/home/president/CryptoPDC/tests/CMakeLists.txt;147;add_test;/home/president/CryptoPDC/tests/CMakeLists.txt;0;")
add_test(CPUCrackerTests "/home/president/CryptoPDC/build/tests/test_cpu_cracker")
set_tests_properties(CPUCrackerTests PROPERTIES  _BACKTRACE_TRIPLES "/home/president/CryptoPDC/tests/CMakeLists.txt;148;add_test;/home/president/CryptoPDC/tests/CMakeLists.txt;0;")
