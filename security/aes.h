/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_AES_H_
#define NDN_SECURITY_AES_H_

#include "../ndn-error-code.h"
#include "tinycrypt/cbc_mode.h"
#include "tinycrypt/constants.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_encrypter {
  const uint8_t* input_value;
  uint8_t input_size;
  uint8_t* output_value;
  uint8_t output_size;
  struct tc_aes_key_sched_struct schedule;
} ndn_encrypter_t;

static inline int
ndn_encrypter_aes_cbc_init(ndn_encrypter_t* encrypter, const uint8_t* input_value, uint8_t input_size,
                           uint8_t* output_value, uint8_t output_size)
{
  if (input_size + TC_AES_BLOCK_SIZE > output_size) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  encrypter->input_value = input_value;
  encrypter->input_size = input_size;
  encrypter->output_value = output_value;
  encrypter->output_size = output_size;
  return 0;
}

int
ndn_encrypter_aes_cbc_encrypt(ndn_encrypter_t* encrypter, const uint8_t* aes_iv,
                              const uint8_t* key_value, uint8_t key_size);

typedef struct ndn_decrypter {
  const uint8_t* input_value;
  uint8_t input_size;
  uint8_t* output_value;
  uint8_t output_size;
  struct tc_aes_key_sched_struct schedule;
} ndn_decrypter_t;

static inline int
ndn_decrypter_aes_cbc_init(ndn_decrypter_t* decrypter, const uint8_t* input_value, uint8_t input_size,
                           uint8_t* output_value, uint8_t output_size)
{
  if (output_size < input_size - TC_AES_BLOCK_SIZE) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  decrypter->input_value = input_value;
  decrypter->input_size = input_size;
  decrypter->output_value = output_value;
  decrypter->output_size = output_size;
  return 0;
}

int
ndn_decrypter_aes_cbc_decrypt(ndn_decrypter_t* decrypter,
                              const uint8_t* key_value, uint8_t key_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_AES_H_
