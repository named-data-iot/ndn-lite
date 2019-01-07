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
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to keep an AES-128 key.
 */
typedef struct ndn_aes_key {
  abstract_key_t abs_key;
  /**
   * The KEY ID of current key. Should be unique.
   */
  uint32_t key_id;
} ndn_aes_key_t;

/**
 * Use AES-128-CBC algorithm to encrypt a buffer. This function does not perform any padding.
 * The input_size must be a multiple of NDN_AES_BLOCK_SIZE to obtain a successful encryption.
 * @param input_value. Input. Buffer to encrypt.
 * @param input_size. Input. Size of input buffer.
 * @param output_value. Output. Encrypted buffer.
 * @param output_size. Input. Size of encrypted buffer.
 * @param aes_iv. Input. AES Initialization Vector, whose length should be NDN_AES_BLOCK_SIZE.
 * @param key_value. Input. AES-128 key to perform encryption.
 * @param key_size. Input. Size of used AES-128 key.
 * @return NDN_SUCCESS if there is no error.
 */
int
ndn_aes_cbc_encrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv, const abstract_key_t* abs_key);

/**
 * Use AES-128-CBC algorithm to decrypt an encrypted buffer. This function is implemented without padding.
 * The input_size must be a multiple of NDN_AES_BLOCK_SIZE to obtain a successful decryption.
 * @param input_value. Input. Buffer to decrypt.
 * @param input_size. Input. Size of input buffer.
 * @param output_value. Output. Decrypted buffer.
 * @param output_size. Input. Size of decrypted buffer.
 * @param aes_iv. Input. AES Initialization Vector, whose length should be NDN_AES_BLOCK_SIZE.
 * @param key_value. Input. AES-128 key to perform decryption. Should be same as encryption key.
 * @param key_size. Input. Size of used AES-128 key.
 * @return NDN_SUCCESS if there is no error.
 */
int
ndn_aes_cbc_decrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv, const abstract_key_t* abs_key);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_AES_H_
