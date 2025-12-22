#include "cryptopdc/common/utils.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <cmath>
#include <chrono>
#include <fstream>

#ifdef __linux__
#include <sys/sysinfo.h>
#endif

#ifdef __CUDACC__
#include <cuda_runtime.h>
#endif

namespace cryptopdc {
namespace utils {

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

std::string to_upper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return result;
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string trim(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(),
                                   [](unsigned char c) { return std::isspace(c); });
    auto end = std::find_if_not(str.rbegin(), str.rend(),
                                 [](unsigned char c) { return std::isspace(c); }).base();
    return (start < end) ? std::string(start, end) : std::string();
}

uint64_t calculate_keyspace_size(const std::string& charset, uint32_t length) {
    return static_cast<uint64_t>(std::pow(charset.length(), length));
}

uint64_t calculate_total_keyspace(const std::string& charset, uint32_t min_len, uint32_t max_len) {
    uint64_t total = 0;
    for (uint32_t len = min_len; len <= max_len; ++len) {
        total += calculate_keyspace_size(charset, len);
    }
    return total;
}

void index_to_key(uint64_t index, char* output, const char* charset, int charset_len, int key_length) {
    for (int i = key_length - 1; i >= 0; --i) {
        output[i] = charset[index % charset_len];
        index /= charset_len;
    }
    output[key_length] = '\0';
}

uint64_t key_to_index(const char* key, const char* charset, int charset_len, int key_length) {
    uint64_t index = 0;
    for (int i = 0; i < key_length; ++i) {
        // Find position of character in charset
        int pos = 0;
        for (int j = 0; j < charset_len; ++j) {
            if (key[i] == charset[j]) {
                pos = j;
                break;
            }
        }
        index = index * charset_len + pos;
    }
    return index;
}

double get_current_time_seconds() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration<double>(duration).count();
}

size_t get_available_memory_bytes() {
#ifdef __linux__
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        return info.freeram;
    }
#endif
    return 0;
}

size_t get_gpu_memory_bytes(int device_id) {
#ifdef __CUDACC__
    size_t free_mem, total_mem;
    cudaSetDevice(device_id);
    cudaMemGetInfo(&free_mem, &total_mem);
    return free_mem;
#else
    (void)device_id;
    return 0;
#endif
}

} // namespace utils
} // namespace cryptopdc
