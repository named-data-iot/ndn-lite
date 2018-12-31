/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "../ndn-lite-sec-config.h"

#ifdef NDN_LITE_SEC_BACKEND_AES_DEFAULT

#include "../ndn-lite-aes.h"
#include "../detail/sec-lib/tinycrypt/tc_cbc_mode.h"
#include "../detail/sec-lib/tinycrypt/tc_constants.h"

int
ndn_aes_cbc_encrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv,
                    const uint8_t* key_value, uint8_t key_size)
{
  if (input_size + TC_AES_BLOCK_SIZE > output_size || key_size < 16) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  struct tc_aes_key_sched_struct schedule;
  tc_aes128_set_encrypt_key(&schedule, key_value);
  if (tc_cbc_mode_encrypt(output_value, input_size + TC_AES_BLOCK_SIZE,
                          input_value, input_size, aes_iv, &schedule) == 0) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  return 0;
}

int
ndn_aes_cbc_decrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv,
                    const uint8_t* key_value, uint8_t key_size)
{
  if (output_size < input_size - TC_AES_BLOCK_SIZE || key_size < 16) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  (void)aes_iv;
  struct tc_aes_key_sched_struct schedule;
  tc_aes128_set_decrypt_key(&schedule, key_value);
  if (tc_cbc_mode_decrypt(output_value, input_size - TC_AES_BLOCK_SIZE,
                          input_value + TC_AES_BLOCK_SIZE, input_size - TC_AES_BLOCK_SIZE,
                          input_value, &schedule) == 0) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  return 0;
}

#endif // NDN_LITE_SEC_BACKEND_AES_DEFAULT