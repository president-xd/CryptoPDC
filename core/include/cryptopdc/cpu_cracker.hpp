#pragma once

#include <string>
#include <vector>
#include <functional>

namespace cryptopdc {
namespace cpu {

struct CrackResult {
    bool found;
    std::string key;
    uint64_t iterations;
};

class CPUCracker {
public:
    static CrackResult crack_dictionary(
        const std::string& algorithm,
        const std::string& target_hash,
        const std::string& wordlist_path
    );

    static CrackResult crack_brute_force(
        const std::string& algorithm,
        const std::string& target_hash,
        const std::string& charset,
        int min_length,
        int max_length,
        uint64_t start_index = 0,
        uint64_t max_iterations = 0
    );
};

} // namespace cpu
} // namespace cryptopdc
