#ifndef NDN_LITE_HMAC_TINYCRIPT_IMPL_H
#define NDN_LITE_HMAC_TINYCRIPT_IMPL_H

#include <stddef.h>
#include <stdint.h>

#include "../../ndn-lite-crypto-key.h"

int
ndn_lite_hmac_sha256_tinycrypt(const uint8_t* key, unsigned int key_size,
                               const void* data, unsigned int data_length,
                               uint8_t* hmac_result);

int
ndn_lite_hmac_make_key_tinycrypt(ndn_hmac_key_t* key, uint32_t key_id,
                                 const uint8_t* input_value, uint32_t input_size,
                                 const uint8_t* personalization, uint32_t personalization_size,
                                 const uint8_t* seed_value, uint32_t seed_size,
                                 const uint8_t* additional_value, uint32_t additional_size,
                                 uint32_t salt_size);

#endif // NDN_LITE_HMAC_TINYCRIPT_IMPL_H
