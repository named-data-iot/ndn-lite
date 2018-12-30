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

/*
 * Interface for AES CBC encryption
 */
int
ndn_aes_cbc_encrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv,
                    const uint8_t* key_value, uint8_t key_size);

/*
 * Interface for AES CBC decryption
 */
int
ndn_aes_cbc_decrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv,
                    const uint8_t* key_value, uint8_t key_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_AES_H_
