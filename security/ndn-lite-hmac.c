/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_SECURITY_AES_H_
#define NDN_SECURITY_AES_H_

#include "ndn-lite-hmac.h"
#include "ndn-lite-sec-utils.h"
#include "../ndn-constants.h"
#include <string.h>

ndn_hmac_backend_t ndn_hmac_backend;

ndn_hmac_backend_t*
ndn_hmac_get_backend(void)
{
  return &ndn_hmac_backend;
}

uint32_t
ndn_hmac_get_key_size(const ndn_hmac_key_t* hmac_key)
{
  return ndn_hmac_backend.get_key_size(&hmac_key->abs_key);
}

const uint8_t*
ndn_hmac_get_key_value(const ndn_hmac_key_t* hmac_key)
{
  return ndn_hmac_backend.get_key_value(&hmac_key->abs_key);
}

int
ndn_hmac_load_key(ndn_hmac_key_t* hmac_key,
                  const uint8_t* key_value, uint32_t key_size)
{
  return ndn_hmac_backend.load_key(&hmac_key->abs_key, key_value, key_size);
}

int
ndn_hmac_sha256_init(ndn_hmac_sha256_state_t* state, const ndn_hmac_key_t* hmac_key)
{
  return ndn_hmac_backend.hmac_sha256_init(&state->abs_state, &hmac_key->abs_key);
}

int
ndn_hmac_sha256_update(ndn_hmac_sha256_state_t* state, const void* payload, uint32_t payload_length)
{
  return ndn_hmac_backend.hmac_sha256_update(&state->abs_state, payload, payload_length);
}

int
ndn_hmac_sha256_final(ndn_hmac_sha256_state_t* state, uint8_t* hmac_result)
{
  return ndn_hmac_backend.hmac_sha256_final(&state->abs_state, hmac_result);
}

int
ndn_hmac_sha256(const void* payload, uint32_t payload_length,
                const ndn_hmac_key_t* hmac_key, uint8_t* hmac_result)
{
  ndn_hmac_sha256_state_t s;
  if (ndn_hmac_sha256_init(&s, hmac_key) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  if (ndn_hmac_sha256_update(&s, payload, payload_length) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  if (ndn_hmac_sha256_final(&s, hmac_result) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return NDN_SUCCESS;
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
ndn_hmac_make_key(ndn_hmac_key_t* hmac_key, uint32_t key_id,
                  const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* personalization, uint32_t personalization_size,
                  const uint8_t* seed_value, uint32_t seed_size,
                  const uint8_t* additional_value, uint32_t additional_size,
                  uint32_t salt_size)
{
  hmac_key->key_id = key_id;
  uint8_t salt[salt_size];
  int r = ndn_hmacprng(personalization, personalization_size,
                       salt, sizeof(salt), seed_value, seed_size,
                       additional_value, additional_size);

  if (r != NDN_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;

  uint8_t key_bytes[NDN_SEC_SHA256_HASH_SIZE] = {0};
  r = ndn_hkdf(input_value, input_size, key_bytes, NDN_SEC_SHA256_HASH_SIZE,
               salt, sizeof(salt), NULL, 0);
  if (r != NDN_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  ndn_hmac_load_key(hmac_key, key_bytes, NDN_SEC_SHA256_HASH_SIZE);
  return NDN_SUCCESS;
}

int
ndn_hkdf(const uint8_t* input_value, uint32_t input_size,
         uint8_t* output_value, uint32_t output_size,
         const uint8_t* seed_value, uint32_t seed_size,
         const uint8_t* info_value, uint32_t info_size)
{
  // parameter check
  if (input_size < 0 || seed_size < 0
      || output_size > NDN_SEC_HMAC_MAX_OUTPUT_SIZE
      || info_size < 0) {
    return NDN_INVALID_ARG;
  }

  // state
  uint8_t previous_output[NDN_SEC_SHA256_HASH_SIZE] = {0};
  uint8_t okm[NDN_SEC_HMAC_MAX_OUTPUT_SIZE] = {0};

  // HKDF extract
  uint8_t prk_bytes[NDN_SEC_SHA256_HASH_SIZE] = {0};
  ndn_hmac_key_t seed_key;
  if (seed_size == 0) {
    ndn_hmac_load_key(&seed_key, previous_output, NDN_SEC_SHA256_HASH_SIZE);
  }
  else {
    ndn_hmac_load_key(&seed_key, seed_value, seed_size);
  }
  if (ndn_hmac_sha256(input_value, input_size, &seed_key, prk_bytes) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  // load prk
  ndn_hmac_key_t prk;
  ndn_hmac_load_key(&prk, prk_bytes, NDN_SEC_SHA256_HASH_SIZE);

  // HKDF expand
  int N = output_size / NDN_SEC_SHA256_HASH_SIZE;
  if (output_size % NDN_SEC_SHA256_HASH_SIZE)
    N += 1;
  for (int i = 1; i <= N; i++) {
    ndn_hmac_sha256_state_t state;
    ndn_hmac_sha256_init(&state, &prk);
    ndn_hmac_sha256_update(&state, previous_output, i == 1 ? 0 : NDN_SEC_SHA256_HASH_SIZE);
    ndn_hmac_sha256_update(&state, info_value, info_size);
    ndn_hmac_sha256_update(&state, &i, 1);
    ndn_hmac_sha256_final(&state, previous_output);
    memcpy(okm + (i - 1) * NDN_SEC_SHA256_HASH_SIZE, previous_output, NDN_SEC_SHA256_HASH_SIZE);
  }
  memcpy(output_value, okm, output_size);
  return NDN_SUCCESS;
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
