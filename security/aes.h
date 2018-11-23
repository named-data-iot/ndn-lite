/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_AES_H_
#define NDN_SECURITY_AES_H_

#include "../encode/name.h"
#include "../ndn-constants.h"
#include "tinycrypt/cbc_mode.h"
#include "tinycrypt/constants.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_encrypter {
  uint8_t* input_value;
  uint8_t input_size;
  uint8_t* output_value;
  uint8_t output_size;
  struct tc_aes_key_sched_struct cipher;
} ndn_encrypter_t;

typedef struct ndn_decrypter {
  uint8_t* input_value;
  uint8_t input_size;
  uint8_t* output_value;
  uint8_t output_size;
  struct tc_aes_key_sched_struct cipher;
} ndn_decrypter_t;

static inline void
ndn_encrypter_init(ndn_encrypter_t* encrypter, const uint8_t* key_value, const uint8_t key_size)
{
  if (key_size < 16)
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  tc_aes128_set_encrypt_key(&encrypter->cipher, key_value);
  return 0;
}

static inline int
ndn_encrypter_set_buffer(ndn_encrypter_t* encrypter, uint8_t* input_value, uint8_t input_size, 
                         uint8_t* output_value, uint8_t output_size)
{
  if (input_size != TC_AES_BLOCK_SIZE  ||
      output_size != TC_AES_BLOCK_SIZE)
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  encrypter->input_value = input_value;
  encrypter->input_size = input_size;
  encrypter->output_value = output_value;
  encrypter->output_size = output_size;
  return 0;
}

static inline int
ndn_encrypter_cbc_set_buffer(ndn_encrypter_t* encrypter, uint8_t* input_value, uint8_t input_size, 
                         uint8_t* output_value, uint8_t output_size)
{
  if (input_size + TC_AES_BLOCK_SIZE != output_size)
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  encrypter->input_value = input_value;
  encrypter->input_size = input_size;
  encrypter->output_value = output_value;
  encrypter->output_size = output_size;
  return 0;
}

int
ndn_encrypter_encrypt(ndn_encrypter_t* encrypter)
{
  if (tc_aes_encrypt(encrypter->output_value, encrypter->input_value, &encrypter->cipher) == 0)
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  return 0; 
}

int
ndn_encrypter_cbc_encrypt(ndn_encrypter_t* encrypter, uint8_t* aes_iv)
{
  if (tc_cbc_mode_encrypt(encrypter->output_value, encrypter->input_size + TC_AES_BLOCK_SIZE,
      encrypter->input_value, encrypter->input_size, aes_iv, &encrypter->cipher) == 0)
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  return 0; 
}

static inline int
ndn_decrypter_init(ndn_decrypter_t* decrypter, const uint8_t* key_value, const uint8_t key_size)
{
  if (key_size < 16)
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  tc_aes128_set_encrypt_key(&decrypter->cipher, key_value);
  return 0;
}

static inline int
ndn_decrypter_set_buffer(ndn_decrypter_t* decrypter, uint8_t* input_value, uint8_t input_size, 
                         uint8_t* output_value, uint8_t output_size)
{
  if (input_size != TC_AES_BLOCK_SIZE  ||
      output_size != TC_AES_BLOCK_SIZE)
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  decrypter->input_value = input_value;
  decrypter->input_size = input_size;
  decrypter->output_value = output_value;
  decrypter->output_size = output_size;
  return 0;
}

static inline int
ndn_decrypter_cbc_set_buffer(ndn_decrypter_t* decrypter, uint8_t* input_value, uint8_t input_size, 
                         uint8_t* output_value, uint8_t output_size)
{
  if (output_size != input_size) 
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  decrypter->input_value = input_value;
  decrypter->input_size = input_size;
  decrypter->output_value = output_value;
  decrypter->output_size = output_size;
  return 0;
}

int
ndn_decrypter_decrypt(ndn_decrypter_t* decrypter)
{
  if (tc_aes_decrypt(decrypter->output_value, decrypter->input_value, &decrypter->cipher) == 0)
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  return 0; 
}

int
ndn_decrypter_cbc_decrypt(ndn_decrypter_t* decrypter, uint8_t* aes_iv)
{
  uint8_t* input_start = decrypter->input_value + TC_AES_BLOCK_SIZE;
  if (tc_cbc_mode_decrypt(decrypter->output_value, decrypter->output_size, 
      input_start, decrypter->input_size, aes_iv, &decrypter->cipher) == 0) 
  {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  return 0;
}

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_AES_H_
