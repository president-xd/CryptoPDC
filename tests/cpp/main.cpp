#include <gtest/gtest.h>
#include <iostream>

int main(int argc, char** argv) {
    std::cout << "==================================================" << std::endl;
    std::cout << "     CryptoPDC Test Suite                         " << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << std::endl;
    
    ::testing::InitGoogleTest(&argc, argv);
    
    // Enable colored output
    ::testing::GTEST_FLAG(color) = "yes";
    
    // Run all tests
    int result = RUN_ALL_TESTS();
    
    std::cout << std::endl;
    std::cout << "==================================================" << std::endl;
    if (result == 0) {
        std::cout << "     All tests passed!                            " << std::endl;
    } else {
        std::cout << "     Some tests failed!                           " << std::endl;
    }
    std::cout << "==================================================" << std::endl;
    
    return result;
}
