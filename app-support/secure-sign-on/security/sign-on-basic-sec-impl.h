/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BLE_BASIC_SEC_IMPL_H
#define SIGN_ON_BLE_BASIC_SEC_IMPL_H

#include <stdint.h>
#include <stddef.h>

#include "../../../security/default-backend/sec-lib/micro-ecc/uECC.h"

int sign_on_basic_gen_sha256_hash(const uint8_t *payload, uint32_t payload_len, uint8_t *output);

int sign_on_basic_aes_cbc_decrypt(uint8_t *key, uint32_t key_len, 
                                           const uint8_t *encrypted_payload, uint32_t encrypted_payload_len,
                                           uint8_t *decrypted_payload, uint32_t decrypted_payload_buf_len);

int sign_on_basic_vrfy_hmac_sha256_sig(const uint8_t *payload, uint32_t payload_len,
                                                  const uint8_t *sig, uint32_t sig_len,
                                                  const uint8_t *key, uint32_t key_len);

int sign_on_basic_gen_sha256_ecdsa_sig(const uint8_t *pri_key_raw, uECC_Curve curve,
                                                const uint8_t *payload, uint32_t payload_len,
                                                uint8_t *output_buf, uint32_t output_buf_len, 
                                                uint32_t *output_len);

int sign_on_basic_gen_ecdh_shared_secret(const uint8_t *pub_key_raw, uint32_t pub_key_raw_len,
                                                    const uint8_t *pri_key_raw, uint32_t pri_key_raw_len,
                                                    uECC_Curve curve,
                                                    uint8_t *output_buf, uint32_t output_buf_len, 
                                                    uint32_t *output_len);

int sign_on_basic_gen_ec_keypair(uint8_t *pub_key_buf, uint32_t pub_key_buf_len, 
                                            uint32_t *pub_key_output_len,
                                            uint8_t *pri_key_buf, uint32_t pri_key_buf_len, 
                                            uint32_t *pri_key_output_len,
                                            uECC_Curve curve);

#endif // SIGN_ON_BLE_BASIC_SEC_IMPL_H
