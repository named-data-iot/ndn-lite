/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_SIGN_VERIFY_H_
#define NDN_SECURITY_SIGN_VERIFY_H_

#include "../encode/name.h"

#ifdef __cplusplus
extern "C" {
#endif

int
ndn_signer_sha256_sign(const uint8_t* input_value, uint32_t input_size,
                       uint8_t* output_value, uint32_t output_max_size,
                       uint32_t* output_used_size);

int
ndn_signer_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value, uint32_t output_max_size,
                      const uint8_t* prv_key_value, uint32_t prv_key_size,
                      uint8_t ecdsa_type, uint32_t* output_used_size);

int
ndn_signer_hmac_sign(const uint8_t* input_value, uint32_t input_size,
                     uint8_t* output_value, uint32_t output_max_size,
                     const uint8_t* key_value, uint32_t key_size,
                     uint32_t* output_used_size);

int
ndn_verifier_sha256_verify(const uint8_t* input_value, uint32_t input_size,
                           const uint8_t* sig_value, uint32_t sig_size);

int
ndn_verifier_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                          const uint8_t* sig_value, uint32_t sig_size,
                          const uint8_t* pub_key_value,
                          uint32_t pub_key_size, uint8_t ecdsa_type);

int
ndn_verifier_hmac_verify(const uint8_t* input_value, uint32_t input_size,
                         const uint8_t* sig_value, uint32_t sig_size,
                         const uint8_t* key_value, uint32_t key_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_SIGN_VERIFY_H_
