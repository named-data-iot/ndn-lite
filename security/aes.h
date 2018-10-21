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
#include "../encode/ndn_constants.h"
#include <crypto/ciphers.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_encrypter {
  uint8_t* input_value;
  uint8_t input_size;
  uint32_t after_padding_size;
  cipher_t cipher;
} ndn_encrypter_t;

static inline void
ndn_encrypter_init(ndn_encrypter_t* encrypter, const uint8_t* key_value, uint32_t key_size)
{
  cipher_init(&encrypter->cipher, CIPHER_AES_128, key_value, key_size);
}

// call this function after init the encrypter/decrypter
uint32_t
ndn_encrypter_encrypt(ndn_encrypter_t* encrypter, uint8_t* aes_iv,
                      uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value);

typedef struct ndn_decrypter {
  uint8_t* output_value;
  uint32_t output_size;
  uint8_t* after_padding_value;
  cipher_t cipher;
} ndn_decrypter_t;

static inline void
ndn_decrypter_init(ndn_decrypter_t* decrypter, const uint8_t* key_value, uint32_t key_size)
{
  cipher_init(&decrypter->cipher, CIPHER_AES_128, key_value, key_size);
}

// call this function after init the encrypter/decrypter
uint32_t
ndn_decrypter_decrypt(ndn_decrypter_t* decrypter, uint8_t* aes_iv,
                      uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value);

// call this function before encryption operation
static inline uint32_t
encrypter_get_padding_size(ndn_encrypter_t* encrypter, uint32_t input_size)
{
  uint32_t extra = input_size % NDN_AES_BLOCK_SIZE;
  if (extra != 0) {
    encrypter->after_padding_size = input_size + NDN_AES_BLOCK_SIZE - input_size % NDN_AES_BLOCK_SIZE;
  }
  else {
    encrypter->after_padding_size = input_size;
  }
  return encrypter->after_padding_size;
}

// call this after decryption operation
// using ISO/IEC 7816-4
static inline uint32_t
decrypter_unpadding(ndn_decrypter_t* decrypter, uint8_t* after_padding, uint32_t after_padding_size)
{
  uint32_t offset = after_padding_size;
  uint8_t* tail = after_padding + after_padding_size;
  while (*tail == 0x00){
    tail -= 1;
    offset -= 1;
  }
  memcpy(decrypter->output_value, after_padding, offset - 1);
  return offset - 1;
}

// using ISO/IEC 7816-4
static inline void
encrypter_padding(ndn_encrypter_t* encrypter, uint8_t* after_padding, uint32_t after_padding_size)
{
  memset(after_padding, 0, after_padding_size);
  memcpy(after_padding, encrypter->input_value, encrypter->input_size);
  after_padding[encrypter->input_size] = 0x80;
}
#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_AES_H_
