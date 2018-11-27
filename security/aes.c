/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "aes.h"

int
ndn_encrypter_aes_cbc_encrypt(ndn_encrypter_t* encrypter, const uint8_t* aes_iv,
                              const uint8_t* key_value, uint8_t key_size)
{
  if (key_size < 16) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  tc_aes128_set_encrypt_key(&encrypter->schedule, key_value);
  if (tc_cbc_mode_encrypt(encrypter->output_value, encrypter->input_size + TC_AES_BLOCK_SIZE,
                          encrypter->input_value, encrypter->input_size,
                          aes_iv, &encrypter->schedule) == 0) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  return 0;
}

int
ndn_decrypter_aes_cbc_decrypt(ndn_decrypter_t* decrypter,
                              const uint8_t* key_value, uint8_t key_size)
{
  if (key_size < 16) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  tc_aes128_set_decrypt_key(&decrypter->schedule, key_value);
  if (tc_cbc_mode_decrypt(decrypter->output_value, decrypter->input_size - TC_AES_BLOCK_SIZE,
                          decrypter->input_value + TC_AES_BLOCK_SIZE, decrypter->input_size - TC_AES_BLOCK_SIZE,
                          decrypter->input_value, &decrypter->schedule) == 0) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  return 0;
}
