import sys
sys.path.append('python')
import cryptopdc.bindings.cryptopdc_bindings as core
import time

target = "5f4dcc3b5aa765d61d8327deb882cf99" # password
wordlist = "/home/president/crytoPDC/wordlists/common.txt"

start = time.time()
found, key, iterations = core.crack_dictionary("md5", target, wordlist)
end = time.time()

print(f"Dictionary: Found={found}, Key='{key}', Iterations={iterations}, Time={end-start:.6f}s")

target_a = "0cc175b9c0f1b6a831c399e269772661" # a
start = time.time()
# Brute force length 1..5
# Note: C++ crack_brute_force loops length min..max?
# Yes, I implemented it to loop len from min to max.
found, key, iterations = core.crack_brute_force_cpu("md5", target_a, "abcdefghijklmnopqrstuvwxyz", 1, 5)
end = time.time()
print(f"Brute Force: Found={found}, Key='{key}', Iterations={iterations}, Time={end-start:.6f}s")
