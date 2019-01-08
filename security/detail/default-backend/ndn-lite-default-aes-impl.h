/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_AES_TINYCRIPT_IMPL_H
#define NDN_LITE_AES_TINYCRIPT_IMPL_H

#include <stdint.h>

struct abstract_aes_key {
  /**
   * The key bytes buffer of current key.
   */
  uint8_t key_value[32];
  /**
   * The key size of key bytes.
   */
  uint32_t key_size;
};

int
ndn_lite_default_aes_cbc_encrypt(const uint8_t* input_value, uint8_t input_size,
                                 uint8_t* output_value, uint8_t output_size,
                                 const uint8_t* aes_iv, const struct abstract_aes_key* aes_key);

int
ndn_lite_default_aes_cbc_decrypt(const uint8_t* input_value, uint8_t input_size,
                                 uint8_t* output_value, uint8_t output_size,
                                 const uint8_t* aes_iv, const struct abstract_aes_key* aes_key);

#endif // NDN_LITE_AES_TINYCRIPT_IMPL_H
