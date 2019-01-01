
#ifndef NDN_LITE_HMAC_TINYCRIPT_IMPL_H
#define NDN_LITE_HMAC_TINYCRIPT_IMPL_H

#include <stddef.h>
#include <stdint.h>

int ndn_lite_hmac_sha256_tinycrypt(const uint8_t* key, unsigned int key_size,
                                   const void* data, unsigned int data_length,
                                   uint8_t* hmac_result);

#endif // NDN_LITE_HMAC_TINYCRIPT_IMPL_H