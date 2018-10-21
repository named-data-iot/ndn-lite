/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "aes.h"
#include <crypto/modes/cbc.h>
#include <hashes/sha256.h>
#include <random.h>

uint32_t
ndn_encrypter_encrypt(ndn_encrypter_t* encrypter, uint8_t* aes_iv,
                      uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value)
{
  encrypter->input_value = input_value;
  encrypter->input_size = input_size;
  uint8_t after_padding[encrypter->after_padding_size];
  encrypter_padding(encrypter, after_padding, encrypter->after_padding_size);
  cipher_encrypt_cbc(&encrypter->cipher, aes_iv, after_padding,
                     encrypter->after_padding_size, output_value);
  return encrypter->input_size;
}

uint32_t
ndn_decrypter_decrypt(ndn_decrypter_t* decrypter, uint8_t* aes_iv,
                      uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value)
{
  decrypter->output_value = output_value;
  uint8_t after_padding[input_size];
  cipher_decrypt_cbc(&decrypter->cipher, aes_iv, input_value,
                     input_size, after_padding);
  decrypter->output_size = decrypter_unpadding(decrypter, after_padding, input_size);
  return decrypter->output_size;
}
