/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_AES_H_
#define NDN_SECURITY_AES_H_

#include "ndn-lite-hmac.h"
#include "ndn-lite-sec-config.h"
#include "ndn-lite-sec-utils.h"

int
hmac_sha256(const void* payload, uint32_t payload_length,
            const uint8_t* key, uint32_t key_size,
            uint8_t* hmac_result)
{
#ifdef NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
  return ndn_lite_default_hmac_sha256(key, key_size,
                                      payload, payload_length, hmac_result);
#endif
}

int
ndn_hmac_sign(const uint8_t* input_value, uint32_t input_size,
              uint8_t* output_value, uint32_t output_max_size,
              const uint8_t* key_value, uint32_t key_size,
              uint32_t* output_used_size)
{
  if (output_max_size < NDN_SEC_SHA256_HASH_SIZE)
    return NDN_OVERSIZE;
  int ret_val = hmac_sha256(key_value, key_size, input_value, input_size, output_value);
  if (ret_val != NDN_SUCCESS) {
    return ret_val;
  }
  *output_used_size = NDN_SEC_SHA256_HASH_SIZE;
  return NDN_SUCCESS;
}

int
ndn_hmac_verify(const uint8_t* input_value, uint32_t input_size,
                const uint8_t* sig_value, uint32_t sig_size,
                const uint8_t* key_value, uint32_t key_size)
{
  if (sig_size != NDN_SEC_SHA256_HASH_SIZE)
    return NDN_SEC_WRONG_SIG_SIZE;

  uint8_t input_hmac[NDN_SEC_SHA256_HASH_SIZE] = {0};
  hmac_sha256(key_value, key_size, input_value, input_size, input_hmac);
  if (ndn_const_time_memcmp(input_hmac, sig_value, sizeof(input_hmac)) != 0)
    return NDN_SEC_FAIL_VERIFY_SIG;
  else
    return NDN_SUCCESS;
}

int
ndn_hmac_make_key(ndn_hmac_key_t* key, uint32_t key_id,
                  const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* personalization, uint32_t personalization_size,
                  const uint8_t* seed_value, uint32_t seed_size,
                  const uint8_t* additional_value, uint32_t additional_size,
                  uint32_t salt_size)
{
  key->key_id = key_id;
  int result = 0;
#ifdef NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
  result = ndn_lite_default_make_hmac_key(key->key_value, &key->key_size,
                                        input_value, input_size,
                                        personalization, personalization_size,
                                        seed_value, seed_size,
                                        additional_value, additional_size,
                                        salt_size);
#endif
  return result;
}

int
ndn_hkdf(const uint8_t* input_value, uint32_t input_size,
         uint8_t* output_value, uint32_t output_size,
         const uint8_t* seed_value, uint32_t seed_size)
{
  #ifdef NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
  return ndn_lite_default_hkdf(input_value, input_size,
                               output_value, output_size,
                               seed_value, seed_size);
  #endif
}

int
ndn_hmacprng(const uint8_t* input_value, uint32_t input_size,
             uint8_t* output_value, uint32_t output_size,
             const uint8_t* seed_value, uint32_t seed_size,
             const uint8_t* additional_value, uint32_t additional_size)
{
#ifdef NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
  return ndn_lite_default_hmacprng(input_value, input_size,
                                   output_value, output_size,
                                   seed_value, seed_size,
                                   additional_value, additional_size);
  #endif
}

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_AES_H_
