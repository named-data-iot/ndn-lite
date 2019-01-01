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

int
ndn_lite_aes_cbc_encrypt_tinycrypt(const uint8_t* input_value, uint8_t input_size,
                                   uint8_t* output_value, uint8_t output_size,
                                   const uint8_t* aes_iv,
                                   const uint8_t* key_value, uint8_t key_size);

int
ndn_lite_aes_cbc_decrypt_tinycrypt(const uint8_t* input_value, uint8_t input_size,
                                   uint8_t* output_value, uint8_t output_size,
                                   const uint8_t* aes_iv,
                                   const uint8_t* key_value, uint8_t key_size);

#endif // NDN_LITE_AES_TINYCRIPT_IMPL_H
