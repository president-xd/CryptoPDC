#ifndef CRYPTOPDC_TEST_UTILS_HPP
#define CRYPTOPDC_TEST_UTILS_HPP

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <chrono>
#include <random>

namespace cryptopdc {
namespace test {

/**
 * Convert byte vector to hexadecimal string
 */
inline std::string to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (auto b : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return ss.str();
}

/**
 * Convert byte array to hexadecimal string
 */
inline std::string to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

/**
 * Convert hexadecimal string to byte vector
 */
inline std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

/**
 * Generate random bytes
 */
inline std::vector<uint8_t> random_bytes(size_t len) {
    std::vector<uint8_t> result(len);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < len; ++i) {
        result[i] = static_cast<uint8_t>(dis(gen));
    }
    return result;
}

/**
 * Generate random string of given length
 */
inline std::string random_string(size_t len, const std::string& charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
    std::string result;
    result.reserve(len);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, charset.size() - 1);
    
    for (size_t i = 0; i < len; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

/**
 * Simple timer for performance testing
 */
class Timer {
public:
    Timer() : start_(std::chrono::high_resolution_clock::now()) {}
    
    void reset() {
        start_ = std::chrono::high_resolution_clock::now();
    }
    
    double elapsed_ms() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - start_).count();
    }
    
    double elapsed_us() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::micro>(end - start_).count();
    }
    
    double elapsed_s() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double>(end - start_).count();
    }
    
private:
    std::chrono::high_resolution_clock::time_point start_;
};

/**
 * Test data generator for hash algorithms
 */
class HashTestData {
public:
    // Standard test vectors
    static const std::vector<std::string>& standard_inputs() {
        static std::vector<std::string> inputs = {
            "",                     // Empty string
            "a",                    // Single char
            "abc",                  // Three chars
            "message digest",       // Two words
            "abcdefghijklmnopqrstuvwxyz",  // Alphabet
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",  // Alphanumeric
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"  // Numeric repeated
        };
        return inputs;
    }
    
    // Boundary length inputs for testing padding
    static std::vector<std::string> boundary_inputs(size_t block_size) {
        std::vector<std::string> inputs;
        
        // Around block boundary
        for (int delta = -2; delta <= 2; ++delta) {
            size_t len = block_size + delta;
            if (len > 0) {
                inputs.push_back(std::string(len, 'a'));
            }
        }
        
        // Around 2 blocks
        for (int delta = -2; delta <= 2; ++delta) {
            size_t len = 2 * block_size + delta;
            inputs.push_back(std::string(len, 'a'));
        }
        
        return inputs;
    }
    
    // Large input for stress testing
    static std::string large_input(size_t size_kb) {
        return std::string(size_kb * 1024, 'x');
    }
};

/**
 * Macro for performance tests
 */
#define BENCHMARK_HASH(algo, iterations) do { \
    Timer timer; \
    for (int i = 0; i < iterations; ++i) { \
        algo.hash("test"); \
    } \
    double elapsed = timer.elapsed_ms(); \
    double per_hash = elapsed / iterations; \
    std::cout << #algo << ": " << iterations << " hashes in " << elapsed << "ms (" \
              << per_hash << "ms per hash, " << (1000.0 / per_hash) << " h/s)" << std::endl; \
} while(0)

} // namespace test
} // namespace cryptopdc

#endif // CRYPTOPDC_TEST_UTILS_HPP
