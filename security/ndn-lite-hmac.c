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
#include "ndn-lite-sec-utils.h"

ndn_hmac_backend_t ndn_hmac_backend;

*ndn_hmac_backend_t
ndn_hmac_get_backend(void)
{
  return &ndn_hmac_backend;
}

int
ndn_hmac_sha256(const void* payload, uint32_t payload_length,
                const ndn_hmac_key_t* hmac_key, uint8_t* hmac_result)
{
  return ndn_hmac_backend.hmac_sha256(&hmac_key->abs_key, payload, payload_length, hmac_result);
}

int
ndn_hmac_sign(const uint8_t* input_value, uint32_t input_size,
              uint8_t* output_value, uint32_t output_max_size,
              const ndn_hmac_key_t* hmac_key,
              uint32_t* output_used_size)
{
  if (output_max_size < NDN_SEC_SHA256_HASH_SIZE)
    return NDN_OVERSIZE;
  int ret_val = ndn_hmac_sha256(input_value, input_size, hmac_key, output_value);
  if (ret_val != NDN_SUCCESS) {
    return ret_val;
  }
  *output_used_size = NDN_SEC_SHA256_HASH_SIZE;
  return NDN_SUCCESS;
}

int
ndn_hmac_verify(const uint8_t* input_value, uint32_t input_size,
                const uint8_t* sig_value, uint32_t sig_size,
                const ndn_hmac_key_t* hmac_key)
{
  if (sig_size != NDN_SEC_SHA256_HASH_SIZE)
    return NDN_SEC_WRONG_SIG_SIZE;

  uint8_t input_hmac[NDN_SEC_SHA256_HASH_SIZE] = {0};
  ndn_hmac_sha256(input_value, input_size, hmac_key, input_hmac);
  if (ndn_const_time_memcmp(input_hmac, sig_value, sizeof(input_hmac)) != NDN_SUCCESS)
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
  return ndn_hmac_backend.make_key(&key->abs_key,
                                   input_value, input_size,
                                   personalization, personalization_size,
                                   seed_value, seed_size,
                                   additional_value, additional_size,
                                   salt_size);
}

int
ndn_hkdf(const uint8_t* input_value, uint32_t input_size,
         uint8_t* output_value, uint32_t output_size,
         const uint8_t* seed_value, uint32_t seed_size)
{
  return ndn_hmac_backend.hkdf(input_value, input_size,
                               output_value, output_size,
                               seed_value, seed_size);
}

int
ndn_hmacprng(const uint8_t* input_value, uint32_t input_size,
             uint8_t* output_value, uint32_t output_size,
             const uint8_t* seed_value, uint32_t seed_size,
             const uint8_t* additional_value, uint32_t additional_size)
{
  return ndn_hmac_backend.hmacprng(input_value, input_size,
                                   output_value, output_size,
                                   seed_value, seed_size,
                                   additional_value, additional_size);
}

#endif // NDN_SECURITY_AES_H_
