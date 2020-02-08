/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-lite-default-hmac-impl.h"
#include "sec-lib/tinycrypt/tc_hmac_prng.h"
#include "sec-lib/tinycrypt/tc_constants.h"
#include "../ndn-lite-hmac.h"
#include "../../ndn-constants.h"
#include "../../ndn-error-code.h"
#include "../../ndn-enums.h"
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
  if (key_size > NDN_SEC_HMAC_MAX_KEY_SIZE) {
    return NDN_SEC_WRONG_KEY_SIZE;
  }
  memset(hmac_key->key_value, 0, NDN_SEC_HMAC_MAX_KEY_SIZE);
  memcpy(hmac_key->key_value, key_value, key_size);
  hmac_key->key_size = key_size;
  return 0;
}

int
ndn_lite_default_hmac_sha256_init(abstract_hmac_sha256_state_t* state, const abstract_hmac_key_t* hmac_key)
{
  (void)memset(&state->s, 0x00, sizeof(struct tc_hmac_state_struct));
  if (tc_hmac_set_key(&state->s, hmac_key->key_value, hmac_key->key_size) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_hmac_init(&state->s) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  return NDN_SUCCESS;
}
int
ndn_lite_default_hmac_sha256_update(abstract_hmac_sha256_state_t* state, const uint8_t* data, uint32_t datalen)
{
  if (tc_hmac_update(&state->s, data, datalen) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  return NDN_SUCCESS;
}
int
ndn_lite_default_hmac_sha256_final(abstract_hmac_sha256_state_t* state, uint8_t* hmac_result)
{
  if (tc_hmac_final(hmac_result, TC_SHA256_DIGEST_SIZE, &state->s) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
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

void
ndn_lite_default_hmac_load_backend(void)
{
  ndn_hmac_backend_t* backend = ndn_hmac_get_backend();
  backend->get_key_size = ndn_lite_default_hmac_get_key_size;
  backend->get_key_value = ndn_lite_default_hmac_get_key_value;
  backend->load_key = ndn_lite_default_hmac_load_key;
  backend->hmac_sha256_init = ndn_lite_default_hmac_sha256_init;
  backend->hmac_sha256_update = ndn_lite_default_hmac_sha256_update;
  backend->hmac_sha256_final = ndn_lite_default_hmac_sha256_final;
  backend->hmacprng = ndn_lite_default_hmacprng;
}
