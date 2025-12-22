#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace cryptopdc {

// Common type definitions
using byte_t = uint8_t;
using byte_vector = std::vector<byte_t>;
using string_vector = std::vector<std::string>;

// Result structure
struct CrackResult {
    bool found;
    std::string plaintext;
    uint64_t iterations;
    double elapsed_seconds;
    std::string worker_id;
    
    CrackResult() : found(false), iterations(0), elapsed_seconds(0.0) {}
};

// Task configuration
struct TaskConfig {
    std::string algorithm;
    std::string attack_mode;
    std::string target;  // Hash or ciphertext
    
    // Keyspace configuration
    std::string charset;
    uint32_t min_length;
    uint32_t max_length;
    
    // Dictionary attack
    std::string dictionary_path;
    
    // Distributed configuration
    uint64_t keyspace_start;
    uint64_t keyspace_end;
    
    // GPU configuration
    bool use_gpu;
    int gpu_device_id;
    
    TaskConfig() 
        : min_length(1), max_length(8), 
          keyspace_start(0), keyspace_end(0),
          use_gpu(true), gpu_device_id(0) {}
};

// Worker statistics
struct WorkerStats {
    uint64_t keys_tested;
    double keys_per_second;
    double gpu_utilization;
    double memory_usage_mb;
    
    WorkerStats() 
        : keys_tested(0), keys_per_second(0.0),
          gpu_utilization(0.0), memory_usage_mb(0.0) {}
};

// Algorithm types
enum class AlgorithmType {
    HASH,
    SYMMETRIC,
    ASYMMETRIC
};

// Attack modes
enum class AttackMode {
    BRUTE_FORCE,
    DICTIONARY,
    HYBRID,
    RULE_BASED
};

// Execution backend
enum class ExecutionBackend {
    CPU,
    GPU,
    AUTO
};

} // namespace cryptopdc
