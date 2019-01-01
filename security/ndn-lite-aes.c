/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-sec-config.h"
#include "ndn-lite-aes.h"

int
ndn_aes_cbc_encrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv,
                    const uint8_t* key_value, uint8_t key_size)
{
  #ifdef NDN_LITE_SEC_BACKEND_AES_DEFAULT
  return ndn_lite_aes_cbc_encrypt_tinycrypt(input_value, input_size,
                                            output_value, output_size,
                                            aes_iv,
                                            key_value, key_size);
  #endif
}

int
ndn_aes_cbc_decrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv,
                    const uint8_t* key_value, uint8_t key_size)
{
  #ifdef NDN_LITE_SEC_BACKEND_AES_DEFAULT
  return ndn_lite_aes_cbc_decrypt_tinycrypt(input_value, input_size,
                                            output_value, output_size,
                                            aes_iv,
                                            key_value, key_size);
  #endif
}
