#include "cryptopdc/cpu_cracker.hpp"
#include "cryptopdc/algorithms/hash/md5.hpp"
#include "cryptopdc/algorithms/hash/sha1.hpp"
#include "cryptopdc/algorithms/hash/sha256.hpp"
#include "cryptopdc/algorithms/hash/sha512.hpp"
#include "cryptopdc/common/utils.hpp"
#include <fstream>
#include <iostream>
#include <omp.h>
#include <memory>
#include <cstring>

namespace cryptopdc {
namespace cpu {

using namespace algorithms::hash;
using algorithms::HashAlgorithm;

// Helper to create algorithm instance
std::unique_ptr<HashAlgorithm> create_algorithm(const std::string& name) {
    if (name == "md5") return std::make_unique<MD5>();
    if (name == "sha1") return std::make_unique<SHA1>();
    if (name == "sha256") return std::make_unique<SHA256>();
    if (name == "sha512") return std::make_unique<SHA512>();
    return nullptr;
}

CrackResult CPUCracker::crack_dictionary(
    const std::string& algorithm,
    const std::string& target_hash,
    const std::string& wordlist_path
) {
    CrackResult final_result = {false, "", 0};
    
    // Convert target hex to bytes for fast comparison
    std::vector<uint8_t> target_bytes;
    try {
        target_bytes = utils::hex_to_bytes(target_hash);
    } catch (...) {
        return final_result; // Invalid hash
    }

    std::ifstream file(wordlist_path);
    if (!file.is_open()) {
        std::cerr << "Could not open wordlist: " << wordlist_path << std::endl;
        return final_result;
    }

    const size_t BATCH_SIZE = 4096;
    std::vector<std::string> batch;
    batch.reserve(BATCH_SIZE);

    std::string line;
    bool found = false;
    uint64_t total_processed = 0;

    // We use a shared flag to stop all threads
    bool stop = false;

    while (std::getline(file, line) && !stop) {
        // Strip carriage return if present (Windows line endings)
        if (!line.empty() && line.back() == '\r') line.pop_back();
        
        batch.push_back(line);

        if (batch.size() >= BATCH_SIZE) {
            #pragma omp parallel
            {
                // Each thread gets its own algorithm instance
                auto algo = create_algorithm(algorithm);
                if (algo) {
                    #pragma omp for
                    for (size_t i = 0; i < batch.size(); i++) {
                        if (stop) continue;

                        std::vector<uint8_t> hash = algo->hash(batch[i]);
                        
                        // Fast comparison
                        if (hash.size() == target_bytes.size() && 
                            std::memcmp(hash.data(), target_bytes.data(), hash.size()) == 0) {
                            
                            #pragma omp critical
                            {
                                if (!stop) {
                                    final_result.found = true;
                                    final_result.key = batch[i];
                                    stop = true;
                                }
                            }
                        }
                    }
                }
            }
            total_processed += batch.size();
            batch.clear();
        }
    }

    // Process remaining
    if (!batch.empty() && !stop) {
        #pragma omp parallel
        {
            auto algo = create_algorithm(algorithm);
            if (algo) {
                #pragma omp for
                for (size_t i = 0; i < batch.size(); i++) {
                    if (stop) continue;
                    std::vector<uint8_t> hash = algo->hash(batch[i]);
                    if (hash.size() == target_bytes.size() && 
                        std::memcmp(hash.data(), target_bytes.data(), hash.size()) == 0) {
                        #pragma omp critical
                        {
                            if (!stop) {
                                final_result.found = true;
                                final_result.key = batch[i];
                                stop = true;
                            }
                        }
                    }
                }
            }
        }
        total_processed += batch.size();
    }
    
    final_result.iterations = total_processed;
    return final_result;
}

CrackResult CPUCracker::crack_brute_force(
    const std::string& algorithm,
    const std::string& target_hash,
    const std::string& charset,
    int min_length,
    int max_length,
    uint64_t start_index,
    uint64_t max_iterations
) {
    CrackResult final_result = {false, "", 0};
    
    std::vector<uint8_t> target_bytes;
    try {
        target_bytes = utils::hex_to_bytes(target_hash);
    } catch (...) {
        return final_result;
    }

    // Calculate total keyspace if max_iterations is 0 (meaning all)
    // But for brute force, we usually loop through lengths.
    // Here we simplified: the caller might call this per length?
    // Or we loop lengths here.
    // For OpenMP, looping per length is easier.
    
    bool stop = false;
    uint64_t total_processed = 0;

    for (int len = min_length; len <= max_length; ++len) {
        if (stop) break;

        // Calculate size for this length
        uint64_t size = 1;
        for (int i = 0; i < len; i++) size *= charset.length();

        // If max_iterations is set, we might need to limit, but usually brute force runs until done
        // For distributed, we'd take start/end. 
        // Assuming this function runs the WHOLE range for now as per `worker.py` logic.
        
        #pragma omp parallel
        {
            auto algo = create_algorithm(algorithm);
            if (algo) {
                // Thread-private buffer for key generation
                char key_buffer[64]; 
                
                #pragma omp for
                for (uint64_t i = 0; i < size; i++) {
                    if (stop) continue;

                    // Generate key (index to key)
                    // We need a fast implementation here.
                    // utils::index_to_key puts result in buffer.
                    utils::index_to_key(i, key_buffer, charset.c_str(), charset.length(), len);
                    std::string key(key_buffer, len);
                    
                    std::vector<uint8_t> hash = algo->hash(key);
                    
                    if (hash.size() == target_bytes.size() && 
                        std::memcmp(hash.data(), target_bytes.data(), hash.size()) == 0) {
                        
                        #pragma omp critical
                        {
                            if (!stop) {
                                final_result.found = true;
                                final_result.key = key;
                                stop = true;
                            }
                        }
                    }
                }
            }
        }
        total_processed += size;
    }

    final_result.iterations = total_processed;
    return final_result;
}

} // namespace cpu
} // namespace cryptopdc
