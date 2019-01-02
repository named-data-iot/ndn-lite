/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_SHA_H_
#define NDN_SECURITY_SHA_H_

#include "../ndn-error-code.h"
#include "../ndn-constants.h"

#ifdef __cplusplus
extern "C" {
#endif

int
sha256(const uint8_t* data, uint32_t datalen, uint8_t* hash_result);

/**
 * Use SHA-256 Algorithm to sign buffer. Memory buffer to hold the siganture should not smaller than 32 bytes.
 * @param input_value. Input. Buffer prepared to sign.
 * @param input_size. Input. Size of input buffer.
 * @param output_value. Output. Signature value.
 * @param output_max_size. Input. Buffer size of output_value
 * @param output_used_size. Output. Size of used output buffer when signing complete.
 * @return 0 if there is no error.
 */
int
ndn_sha256_sign(const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_max_size,
                uint32_t* output_used_size);

/**
 * Use SHA-256 Algorithm to verify signature. Memory buffer to hold the siganture should not smaller than 32 bytes.
 * @param input_value. Input. SHA-256 Signed buffer.
 * @param input_size. Input. Size of input buffer.
 * @param sig_value. Input. SHA-256 signature value.
 * @param sig_size. Input. SHA-256 signature size.
 * @return 0 if verification succeeded.
 */
int
ndn_sha256_verify(const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* sig_value, uint32_t sig_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_AES_H_
