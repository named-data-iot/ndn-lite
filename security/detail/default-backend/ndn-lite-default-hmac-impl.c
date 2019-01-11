/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-default-hmac-impl.h"
#include "sec-lib/tinycrypt/tc_hmac.h"
#include "sec-lib/tinycrypt/tc_hmac_prng.h"
#include "sec-lib/tinycrypt/tc_constants.h"
#include "../../ndn-lite-hmac.h"
#include "../../../ndn-constants.h"
#include "../../../ndn-error-code.h"
#include "../../../ndn-enums.h"
#include <string.h>

uint32_t
ndn_lite_default_hmac_get_key_size(const struct abstract_hmac_key* hmac_key)
{
  return hmac_key->key_size;
}

const uint8_t*
ndn_lite_default_hmac_get_key_value(const struct abstract_hmac_key* hmac_key)
{
  return hmac_key->key_value;
}

int
ndn_lite_default_hmac_load_key(struct abstract_hmac_key* hmac_key,
                               const uint8_t* key_value, uint32_t key_size)
{
  memset(hmac_key->key_value, 0, 32);
  memcpy(hmac_key->key_value, key_value, key_size);
  hmac_key->key_size = key_size;
  return 0;
}

int
ndn_lite_default_hmac_sha256(const void* data, uint32_t data_length,
                             const struct abstract_hmac_key* abs_key,
                             uint8_t* hmac_result)
{
  struct tc_hmac_state_struct h;
  (void)memset(&h, 0x00, sizeof(h));
  if (tc_hmac_set_key(&h, abs_key->key_value, abs_key->key_size) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_hmac_init(&h) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_hmac_update(&h, data, data_length) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_hmac_final(hmac_result, TC_SHA256_DIGEST_SIZE, &h) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return NDN_SUCCESS;
}

int
ndn_lite_default_hkdf(const uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value, uint32_t output_size,
                      const uint8_t* seed_value, uint32_t seed_size)
{
  uint8_t prk[NDN_SEC_SHA256_HASH_SIZE] = {0};
  struct abstract_hmac_key seed_key;
  ndn_lite_default_hmac_load_key(&seed_key, seed_value, seed_size);
  if (ndn_lite_default_hmac_sha256(input_value, input_size, &seed_key, prk) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  //APP_LOG_HEX("Current value of prk:", prk, NDN_SEC_SHA256_HASH_SIZE);

  int iter;
  if (output_size % NDN_SEC_SHA256_HASH_SIZE)
    iter = output_size / NDN_SEC_SHA256_HASH_SIZE + 1;
  else
    iter = output_size / NDN_SEC_SHA256_HASH_SIZE;
  uint8_t t[NDN_SEC_SHA256_HASH_SIZE] = {0};
  uint8_t cat[NDN_SEC_SHA256_HASH_SIZE + 1] = {0};
  uint8_t okm[NDN_SEC_SHA256_HASH_SIZE * iter];
  for (uint8_t i = 0; i < NDN_SEC_SHA256_HASH_SIZE * iter; i++)
    okm[i] = 0;
  uint8_t table[16] = {0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  uint8_t t_first[1] = {0x01};
  for (int i = 0; i < iter; ++i) {
    if (i == 0) {
      struct abstract_hmac_key t_key;
      ndn_lite_default_hmac_load_key(&t_key, t_first, sizeof(t_first));
      if (ndn_lite_default_hmac_sha256(prk, NDN_SEC_SHA256_HASH_SIZE,
                                       &t_key, t) != NDN_SUCCESS) {
        return NDN_SEC_CRYPTO_ALGO_FAILURE;
      }
      memcpy(okm + i * NDN_SEC_SHA256_HASH_SIZE, t, NDN_SEC_SHA256_HASH_SIZE);
    }
    else {
      memcpy(cat, t, NDN_SEC_SHA256_HASH_SIZE);
      cat[NDN_SEC_SHA256_HASH_SIZE] = table[i];
      struct abstract_hmac_key cat_key;
      ndn_lite_default_hmac_load_key(&cat_key, cat, NDN_SEC_SHA256_HASH_SIZE+1);
      if (ndn_lite_default_hmac_sha256(prk, NDN_SEC_SHA256_HASH_SIZE, &cat_key, t) != NDN_SUCCESS) {
        return NDN_SEC_CRYPTO_ALGO_FAILURE;
      }
      memcpy(okm + i * NDN_SEC_SHA256_HASH_SIZE, t, NDN_SEC_SHA256_HASH_SIZE);
    }
  }
  memcpy(output_value, okm, output_size);
  return NDN_SUCCESS;
}

int
ndn_lite_default_hmacprng(const uint8_t* input_value, uint32_t input_size,
                          uint8_t* output_value, uint32_t output_size,
                          const uint8_t* seed_value, uint32_t seed_size,
                          const uint8_t* additional_value, uint32_t additional_size)
{
  struct tc_hmac_prng_struct h;
  if (tc_hmac_prng_init(&h, input_value, input_size) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }

  if (seed_size < 32) {
    uint8_t min_seed[32] = {0};
    memcpy(min_seed, seed_value, seed_size);
    if (tc_hmac_prng_reseed(&h, min_seed, sizeof(min_seed),
                            additional_value, additional_size) != TC_CRYPTO_SUCCESS) {
      return NDN_SEC_INIT_FAILURE;
    }
    if (tc_hmac_prng_generate(output_value, output_size, &h) != TC_CRYPTO_SUCCESS) {
      return NDN_SEC_CRYPTO_ALGO_FAILURE;
    }
  }
  else {
    if (tc_hmac_prng_reseed(&h, seed_value, seed_size,
                            additional_value, additional_size) != TC_CRYPTO_SUCCESS) {
      return NDN_SEC_INIT_FAILURE;
    }
    if (tc_hmac_prng_generate(output_value, output_size, &h) != TC_CRYPTO_SUCCESS) {
      return NDN_SEC_CRYPTO_ALGO_FAILURE;
    }
  }
  return NDN_SUCCESS;
}

int
ndn_lite_default_make_key(struct abstract_hmac_key* abs_key,
                          const uint8_t* input_value, uint32_t input_size,
                          const uint8_t* personalization, uint32_t personalization_size,
                          const uint8_t* seed_value, uint32_t seed_size,
                          const uint8_t* additional_value, uint32_t additional_size,
                          uint32_t salt_size)
{
  uint8_t salt[salt_size];
  int r = ndn_lite_default_hmacprng(personalization, personalization_size,
                                    salt, sizeof(salt), seed_value, seed_size,
                                    additional_value, additional_size);

  if (r != NDN_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  abs_key->key_size = NDN_SEC_SHA256_HASH_SIZE;
  r = ndn_lite_default_hkdf(input_value, input_size, abs_key->key_value, abs_key->key_size,
                            salt, sizeof(salt));
  if (r != NDN_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  return NDN_SUCCESS;
}

void
ndn_lite_default_hmac_load_backend(void)
{
  ndn_hmac_backend_t* backend = ndn_hmac_get_backend();
  backend->get_key_size = ndn_lite_default_hmac_get_key_size;
  backend->get_key_value = ndn_lite_default_hmac_get_key_value;
  backend->load_key = ndn_lite_default_hmac_load_key;
  backend->hmac_sha256 = ndn_lite_default_hmac_sha256;
  backend->make_key = ndn_lite_default_make_key;
  backend->hkdf = ndn_lite_default_hkdf;
  backend->hmacprng = ndn_lite_default_hmacprng;
}
