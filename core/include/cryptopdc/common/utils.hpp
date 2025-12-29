#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace cryptopdc {
namespace utils {

// ============================================================================
// Hex encoding/decoding
// ============================================================================
std::string bytes_to_hex(const uint8_t* data, size_t len);
std::vector<uint8_t> hex_to_bytes(const std::string& hex);
bool is_valid_hex(const std::string& str);

// ============================================================================
// Base64 encoding/decoding
// ============================================================================
std::string bytes_to_base64(const uint8_t* data, size_t len);
std::string bytes_to_base64(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_to_bytes(const std::string& base64);
bool is_valid_base64(const std::string& str);

// ============================================================================
// Format conversion helpers
// ============================================================================
std::string hex_to_base64(const std::string& hex);
std::string base64_to_hex(const std::string& base64);

// ============================================================================
// String utilities
// ============================================================================
std::string to_lower(const std::string& str);
std::string to_upper(const std::string& str);
std::vector<std::string> split(const std::string& str, char delimiter);
std::string trim(const std::string& str);

// ============================================================================
// Keyspace utilities
// ============================================================================
uint64_t calculate_keyspace_size(const std::string& charset, uint32_t length);
uint64_t calculate_total_keyspace(const std::string& charset, uint32_t min_len, uint32_t max_len);
void index_to_key(uint64_t index, char* output, const char* charset, int charset_len, int key_length);
uint64_t key_to_index(const char* key, const char* charset, int charset_len, int key_length);

// ============================================================================
// Timing utilities
// ============================================================================
double get_current_time_seconds();

// ============================================================================
// Memory utilities
// ============================================================================
size_t get_available_memory_bytes();
size_t get_gpu_memory_bytes(int device_id);

} // namespace utils
} // namespace cryptopdc
