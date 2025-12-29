#include "cryptopdc/common/utils.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <cmath>
#include <chrono>
#include <fstream>
#include <stdexcept>

#ifdef __linux__
#include <sys/sysinfo.h>
#endif

#ifdef __CUDACC__
#include <cuda_runtime.h>
#endif

namespace cryptopdc {
namespace utils {

// ============================================================================
// Base64 encoding table
// ============================================================================
static const char BASE64_CHARS[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static const int BASE64_DECODE_TABLE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0-15
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 16-31
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  // 32-47 (+, /)
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  // 48-63 (0-9)
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  // 64-79 (A-O)
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  // 80-95 (P-Z)
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  // 96-111 (a-o)
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  // 112-127 (p-z)
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

// ============================================================================
// Hex encoding/decoding
// ============================================================================

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

bool is_valid_hex(const std::string& str) {
    if (str.empty() || str.length() % 2 != 0) {
        return false;
    }
    for (char c : str) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Base64 encoding/decoding
// ============================================================================

std::string bytes_to_base64(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(((len + 2) / 3) * 4);
    
    size_t i = 0;
    while (i < len) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;
        
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        result += BASE64_CHARS[(triple >> 18) & 0x3F];
        result += BASE64_CHARS[(triple >> 12) & 0x3F];
        result += BASE64_CHARS[(triple >> 6) & 0x3F];
        result += BASE64_CHARS[triple & 0x3F];
    }
    
    // Add padding
    size_t mod = len % 3;
    if (mod == 1) {
        result[result.length() - 2] = '=';
        result[result.length() - 1] = '=';
    } else if (mod == 2) {
        result[result.length() - 1] = '=';
    }
    
    return result;
}

std::string bytes_to_base64(const std::vector<uint8_t>& data) {
    return bytes_to_base64(data.data(), data.size());
}

std::vector<uint8_t> base64_to_bytes(const std::string& base64) {
    std::vector<uint8_t> result;
    
    if (base64.empty()) {
        return result;
    }
    
    // Calculate output size (accounting for padding)
    size_t len = base64.length();
    size_t padding = 0;
    if (len >= 2) {
        if (base64[len - 1] == '=') padding++;
        if (base64[len - 2] == '=') padding++;
    }
    
    result.reserve((len * 3) / 4 - padding);
    
    uint32_t buffer = 0;
    int bits_collected = 0;
    
    for (char c : base64) {
        if (c == '=') break;  // Stop at padding
        
        int value = BASE64_DECODE_TABLE[static_cast<unsigned char>(c)];
        if (value < 0) {
            continue;  // Skip invalid characters (whitespace, etc.)
        }
        
        buffer = (buffer << 6) | value;
        bits_collected += 6;
        
        if (bits_collected >= 8) {
            bits_collected -= 8;
            result.push_back(static_cast<uint8_t>((buffer >> bits_collected) & 0xFF));
        }
    }
    
    return result;
}

bool is_valid_base64(const std::string& str) {
    if (str.empty()) {
        return false;
    }
    
    size_t len = str.length();
    
    // Base64 length must be divisible by 4
    if (len % 4 != 0) {
        return false;
    }
    
    // Check all characters
    for (size_t i = 0; i < len; ++i) {
        char c = str[i];
        
        // Padding can only appear at the end
        if (c == '=') {
            if (i < len - 2) {
                return false;
            }
        } else {
            if (BASE64_DECODE_TABLE[static_cast<unsigned char>(c)] < 0) {
                return false;
            }
        }
    }
    
    return true;
}

// ============================================================================
// Format conversion helpers
// ============================================================================

std::string hex_to_base64(const std::string& hex) {
    std::vector<uint8_t> bytes = hex_to_bytes(hex);
    return bytes_to_base64(bytes);
}

std::string base64_to_hex(const std::string& base64) {
    std::vector<uint8_t> bytes = base64_to_bytes(base64);
    return bytes_to_hex(bytes.data(), bytes.size());
}

// ============================================================================
// String utilities
// ============================================================================

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
