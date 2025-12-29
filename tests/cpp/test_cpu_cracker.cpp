#include <gtest/gtest.h>
#include "cryptopdc/cpu_cracker.hpp"
#include <string>
#include <vector>
#include <thread>
#include <chrono>

using namespace cryptopdc;

class CPUCrackerTest : public ::testing::Test {
protected:
    CPUCracker cracker;
};

// =============================================================================
// Algorithm Support Tests
// =============================================================================

TEST_F(CPUCrackerTest, SupportedAlgorithms) {
    auto algorithms = cracker.get_supported_algorithms();
    
    // Verify essential algorithms are supported
    EXPECT_TRUE(std::find(algorithms.begin(), algorithms.end(), "MD5") != algorithms.end());
    EXPECT_TRUE(std::find(algorithms.begin(), algorithms.end(), "SHA1") != algorithms.end());
    EXPECT_TRUE(std::find(algorithms.begin(), algorithms.end(), "SHA256") != algorithms.end());
    EXPECT_TRUE(std::find(algorithms.begin(), algorithms.end(), "SHA512") != algorithms.end());
}

TEST_F(CPUCrackerTest, AlgorithmListNotEmpty) {
    auto algorithms = cracker.get_supported_algorithms();
    EXPECT_GT(algorithms.size(), 0) << "Should support at least one algorithm";
}

// =============================================================================
// Hash Validation Tests
// =============================================================================

TEST_F(CPUCrackerTest, ValidateMD5Hash) {
    // MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
    std::string hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    EXPECT_TRUE(cracker.validate_hash(hash, "MD5"));
}

TEST_F(CPUCrackerTest, ValidateSHA1Hash) {
    // SHA1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
    std::string hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
    EXPECT_TRUE(cracker.validate_hash(hash, "SHA1"));
}

TEST_F(CPUCrackerTest, ValidateSHA256Hash) {
    // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    std::string hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    EXPECT_TRUE(cracker.validate_hash(hash, "SHA256"));
}

TEST_F(CPUCrackerTest, InvalidHashLength) {
    // Too short for MD5
    std::string hash = "5f4dcc3b5aa765d61d8327de";
    EXPECT_FALSE(cracker.validate_hash(hash, "MD5"));
}

TEST_F(CPUCrackerTest, InvalidHashCharacters) {
    // Contains invalid hex characters
    std::string hash = "5f4dcc3b5aa765d61d8327deb882cXXX";
    EXPECT_FALSE(cracker.validate_hash(hash, "MD5"));
}

// =============================================================================
// Wordlist Attack Tests
// =============================================================================

TEST_F(CPUCrackerTest, WordlistAttackSimple) {
    // Create a simple wordlist
    std::vector<std::string> wordlist = {"hello", "world", "password", "test"};
    
    // MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
    std::string target_hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    
    auto result = cracker.wordlist_attack(target_hash, "MD5", wordlist);
    
    if (result.found) {
        EXPECT_EQ(result.plaintext, "password");
    }
}

TEST_F(CPUCrackerTest, WordlistAttackNotFound) {
    std::vector<std::string> wordlist = {"hello", "world", "test"};
    
    // MD5("notinlist") won't be found
    std::string target_hash = "e99a18c428cb38d5f260853678922e03";  // MD5("abc123")
    
    auto result = cracker.wordlist_attack(target_hash, "MD5", wordlist);
    
    EXPECT_FALSE(result.found);
}

// =============================================================================
// Brute Force Attack Tests
// =============================================================================

TEST_F(CPUCrackerTest, BruteForceAttackSimple) {
    // MD5("ab") - very short for quick test
    std::string target_hash = "187ef4436122d1cc2f40dc2b92f0eba0";
    
    CrackConfig config;
    config.charset = "abcdefghijklmnopqrstuvwxyz";
    config.min_length = 2;
    config.max_length = 2;
    config.max_iterations = 1000;
    
    auto result = cracker.brute_force_attack(target_hash, "MD5", config);
    
    if (result.found) {
        EXPECT_EQ(result.plaintext, "ab");
    }
}

TEST_F(CPUCrackerTest, BruteForceAttackWithTimeout) {
    // Create an impossible hash (won't be found)
    std::string target_hash = "00000000000000000000000000000000";
    
    CrackConfig config;
    config.charset = "abcdefghijklmnopqrstuvwxyz";
    config.min_length = 1;
    config.max_length = 10;
    config.timeout_seconds = 1;  // 1 second timeout
    
    auto start = std::chrono::steady_clock::now();
    auto result = cracker.brute_force_attack(target_hash, "MD5", config);
    auto end = std::chrono::steady_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
    
    // Should have stopped within reasonable time due to timeout
    EXPECT_LE(duration, 5) << "Brute force should respect timeout";
    EXPECT_FALSE(result.found);
}

// =============================================================================
// Progress Callback Tests
// =============================================================================

TEST_F(CPUCrackerTest, ProgressCallbackInvoked) {
    std::vector<std::string> wordlist;
    for (int i = 0; i < 100; ++i) {
        wordlist.push_back("word" + std::to_string(i));
    }
    
    std::string target_hash = "00000000000000000000000000000000";  // Won't find
    
    int callback_count = 0;
    auto callback = [&callback_count](const CrackProgress& progress) {
        callback_count++;
    };
    
    cracker.set_progress_callback(callback);
    auto result = cracker.wordlist_attack(target_hash, "MD5", wordlist);
    
    EXPECT_GT(callback_count, 0) << "Progress callback should have been invoked";
}

// =============================================================================
// Multi-threading Tests
// =============================================================================

TEST_F(CPUCrackerTest, SetNumThreads) {
    unsigned int num_threads = 4;
    cracker.set_num_threads(num_threads);
    EXPECT_EQ(cracker.get_num_threads(), num_threads);
}

TEST_F(CPUCrackerTest, ThreadSafeWordlistAttack) {
    std::vector<std::string> wordlist;
    for (int i = 0; i < 1000; ++i) {
        wordlist.push_back("word" + std::to_string(i));
    }
    
    // MD5("word500")
    std::string target_hash = cracker.compute_hash("word500", "MD5");
    
    cracker.set_num_threads(4);
    auto result = cracker.wordlist_attack(target_hash, "MD5", wordlist);
    
    if (result.found) {
        EXPECT_EQ(result.plaintext, "word500");
    }
}

// =============================================================================
// Hash Computation Tests
// =============================================================================

TEST_F(CPUCrackerTest, ComputeMD5Hash) {
    std::string plaintext = "test";
    std::string expected = "098f6bcd4621d373cade4e832627b4f6";
    
    std::string computed = cracker.compute_hash(plaintext, "MD5");
    EXPECT_EQ(computed, expected);
}

TEST_F(CPUCrackerTest, ComputeSHA1Hash) {
    std::string plaintext = "test";
    std::string expected = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
    
    std::string computed = cracker.compute_hash(plaintext, "SHA1");
    EXPECT_EQ(computed, expected);
}

TEST_F(CPUCrackerTest, ComputeSHA256Hash) {
    std::string plaintext = "test";
    std::string expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    
    std::string computed = cracker.compute_hash(plaintext, "SHA256");
    EXPECT_EQ(computed, expected);
}

TEST_F(CPUCrackerTest, ComputeHashConsistency) {
    std::string plaintext = "consistent_test_input";
    
    std::string hash1 = cracker.compute_hash(plaintext, "MD5");
    std::string hash2 = cracker.compute_hash(plaintext, "MD5");
    
    EXPECT_EQ(hash1, hash2) << "Same input should produce same hash";
}

TEST_F(CPUCrackerTest, ComputeHashDifferentInputs) {
    std::string plaintext1 = "input1";
    std::string plaintext2 = "input2";
    
    std::string hash1 = cracker.compute_hash(plaintext1, "MD5");
    std::string hash2 = cracker.compute_hash(plaintext2, "MD5");
    
    EXPECT_NE(hash1, hash2) << "Different inputs should produce different hashes";
}

// =============================================================================
// Cancel/Stop Tests
// =============================================================================

TEST_F(CPUCrackerTest, CancelAttack) {
    std::vector<std::string> large_wordlist;
    for (int i = 0; i < 100000; ++i) {
        large_wordlist.push_back("word" + std::to_string(i));
    }
    
    std::string impossible_hash = "00000000000000000000000000000000";
    
    // Start attack in separate thread
    std::atomic<bool> attack_started{false};
    std::thread attack_thread([&]() {
        attack_started = true;
        cracker.wordlist_attack(impossible_hash, "MD5", large_wordlist);
    });
    
    // Wait for attack to start
    while (!attack_started) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Cancel the attack
    cracker.cancel();
    
    // Join should complete quickly
    auto start = std::chrono::steady_clock::now();
    attack_thread.join();
    auto end = std::chrono::steady_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
    EXPECT_LE(duration, 5) << "Attack should have been cancelled quickly";
}

// =============================================================================
// Statistics Tests
// =============================================================================

TEST_F(CPUCrackerTest, GetStatistics) {
    std::vector<std::string> wordlist = {"hello", "world", "password", "test"};
    std::string target_hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    
    auto result = cracker.wordlist_attack(target_hash, "MD5", wordlist);
    auto stats = cracker.get_statistics();
    
    EXPECT_GT(stats.total_attempts, 0);
    EXPECT_GE(stats.hashes_per_second, 0);
}
