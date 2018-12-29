/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BLE_BASIC_SEC_IMPL_H
#define SIGN_ON_BLE_BASIC_SEC_IMPL_H

#include <stdint.h>
#include <stddef.h>

#include <uECC.h>

// define the board type here; I think there is a better way to do this than based on board type,
// since many boards will share the same security libraries, but for now I will do it this way...
#define nRF52840

int sign_on_basic_gen_sha256_hash(const uint8_t *payload, uint16_t payload_len, uint8_t *output);

int sign_on_basic_decrypt_aes_cbc_pkcs5pad(uint8_t *key, uint16_t key_len, 
                                           const uint8_t *encrypted_payload, uint16_t encrypted_payload_len,
                                           uint8_t *decrypted_payload, uint16_t *decrypted_payload_len);

int sign_on_basic_vrfy_hmac_sha256_sig(const uint8_t *payload, uint16_t payload_len,
                                                  const uint8_t *sig, uint16_t sig_len,
                                                  const uint8_t *key, uint16_t key_len);

int sign_on_basic_gen_sha256_ecdsa_sig(const uint8_t *pri_key_raw,
                                                const uint8_t *payload, uint16_t payload_len,
                                                uint8_t *output_buf, uint16_t output_buf_len, 
                                                uint16_t *output_len);

int sign_on_basic_gen_ecdh_shared_secret(const uint8_t *pub_key_raw, uint16_t pub_key_raw_len,
                                                    const uint8_t *pri_key_raw, uint16_t pri_key_raw_len,
                                                    uECC_Curve curve,
                                                    uint8_t *output_buf, uint16_t output_buf_len, 
                                                    uint16_t *output_len);

int sign_on_basic_gen_ec_keypair(uint8_t *pub_key_buf, uint16_t pub_key_buf_len, 
                                            uint16_t *pub_key_output_len,
                                            uint8_t *pri_key_buf, uint16_t pri_key_buf_len, 
                                            uint16_t *pri_key_output_len,
                                            uECC_Curve curve);

#endif // SIGN_ON_BLE_BASIC_SEC_IMPL_H