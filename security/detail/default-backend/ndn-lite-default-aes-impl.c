/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-default-aes-impl.h"
#include "sec-lib/tinycrypt/tc_cbc_mode.h"
#include "sec-lib/tinycrypt/tc_constants.h"
#include "../../ndn-lite-aes.h"
#include "../../../ndn-constants.h"
#include <string.h>

uint32_t
ndn_lite_default_aes_get_key_size(const struct abstract_aes_key* aes_key)
{
  return aes_key->key_size;
}

const uint8_t*
ndn_lite_default_aes_get_key_value(const struct abstract_aes_key* aes_key)
{
  return aes_key->key_value;
}

int
ndn_lite_default_aes_load_key(struct abstract_aes_key* aes_key,
                              const uint8_t* key_value, uint32_t key_size)
{
  memset(aes_key->key_value, 0, 32);
  memcpy(aes_key->key_value, key_value, key_size);
  aes_key->key_size = key_size;
  return 0;
}

int
ndn_lite_default_aes_cbc_encrypt(const uint8_t* input_value, uint8_t input_size,
                                 uint8_t* output_value, uint8_t output_size,
                                 const uint8_t* aes_iv, const struct abstract_aes_key* aes_key)
{
  if (input_size + TC_AES_BLOCK_SIZE > output_size || aes_key->key_size < NDN_SEC_AES_MIN_KEY_SIZE) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  struct tc_aes_key_sched_struct schedule;
  if (tc_aes128_set_encrypt_key(&schedule, aes_key->key_value) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_cbc_mode_encrypt(output_value, input_size + TC_AES_BLOCK_SIZE,
                          input_value, input_size, aes_iv, &schedule) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return NDN_SUCCESS;
}

int
ndn_lite_default_aes_cbc_decrypt(const uint8_t* input_value, uint8_t input_size,
                                 uint8_t* output_value, uint8_t output_size,
                                 const uint8_t* aes_iv, const struct abstract_aes_key* aes_key)
{
  if (output_size < input_size - TC_AES_BLOCK_SIZE || aes_key->key_size < NDN_SEC_AES_MIN_KEY_SIZE) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  (void)aes_iv;
  struct tc_aes_key_sched_struct schedule;
  if (tc_aes128_set_decrypt_key(&schedule, aes_key->key_value) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_cbc_mode_decrypt(output_value, input_size - TC_AES_BLOCK_SIZE,
                          input_value + TC_AES_BLOCK_SIZE, input_size - TC_AES_BLOCK_SIZE,
                          input_value, &schedule) == 0) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return NDN_SUCCESS;
}

void
ndn_lite_default_aes_load_backend(void)
{
  ndn_aes_backend_t* backend = ndn_aes_get_backend();
  backend->get_key_size = ndn_lite_default_aes_get_key_size;
  backend->get_key_value = ndn_lite_default_aes_get_key_value;
  backend->load_key = ndn_lite_default_aes_load_key;
  backend->cbc_encrypt = ndn_lite_default_aes_cbc_encrypt;
  backend->cbc_decrypt = ndn_lite_default_aes_cbc_decrypt;
}
