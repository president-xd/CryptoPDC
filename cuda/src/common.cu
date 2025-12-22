#include "cryptopdc/cuda/common.cuh"

namespace cryptopdc {
namespace cuda {

__device__ void index_to_key_device(uint64_t index, char* output,
                                     const char* charset, int charset_len,
                                     int key_length) {
    for (int i = key_length - 1; i >= 0; --i) {
        output[i] = charset[index % charset_len];
        index /= charset_len;
    }
    output[key_length] = '\0';
}

__device__ bool memcmp_device(const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

} // namespace cuda
} // namespace cryptopdc
