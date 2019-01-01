
#ifndef NDN_LITE_SHA256_TINYCRIPT_IMPL_H
#define NDN_LITE_SHA256_TINYCRIPT_IMPL_H

#include <stddef.h>
#include <stdint.h>

int ndn_lite_sha256_tinycript(const uint8_t* data, size_t datalen, uint8_t* hash_result);

#endif // NDN_LITE_SHA256_TINYCRIPT_IMPL_H