/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_ECC_256_SEC_H
#define SIGN_ON_BASIC_ECC_256_SEC_H

#include <stdint.h>
#include <stddef.h>

int sign_on_basic_ecc_256_gen_sha256_hash(const uint8_t *payload, uint16_t payload_len, uint8_t *output);

int sign_on_basic_ecc_256_decrypt_kd_pri(uint8_t *key, uint16_t key_len, const uint8_t *encrypted_payload, 
                                                       uint16_t encrypted_payload_len, uint8_t *decrypted_payload, 
                                                       uint16_t *decrypted_payload_len);

int sign_on_basic_ecc_256_vrfy_btstrp_rqst_rspns_sig(const uint8_t *payload, uint16_t payload_len,
                                                                const uint8_t *sig, uint16_t sig_len,
                                                                const uint8_t *key, uint16_t key_len);

int sign_on_basic_ecc_256_vrfy_cert_rqst_rspns_sig(const uint8_t *payload, uint16_t payload_len,
                                                                const uint8_t *sig, uint16_t sig_len,
                                                                const uint8_t *key, uint16_t key_len);

int sign_on_basic_ecc_256_gen_cert_rqst_sig(const uint8_t *pri_key, const uint8_t *payload, 
                                                   uint16_t payload_len, uint8_t *output_buf,  
                                                   uint16_t output_buf_len, uint16_t *output_len);

int sign_on_basic_ecc_256_gen_btstrp_rqst_sig(const uint8_t *pri_key, const uint8_t *payload, 
                                                   uint16_t payload_len, uint8_t *output_buf,  
                                                   uint16_t output_buf_len, uint16_t *output_len);

int sign_on_basic_ecc_256_gen_fin_msg_sig(const uint8_t *pri_key, const uint8_t *payload, 
                                                   uint16_t payload_len, uint8_t *output_buf,  
                                                   uint16_t output_buf_len, uint16_t *output_len);

int sign_on_basic_ecc_256_gen_n1_keypair(uint8_t *pub_key_buf, uint16_t pub_key_buf_len, 
                                         uint16_t *pub_key_output_len,
                                         uint8_t *pri_key_buf, uint16_t pri_key_buf_len, 
                                         uint16_t *pri_key_output_len);

int sign_on_basic_ecc_256_gen_kt(const uint8_t *pub_key, uint16_t pub_key_len,
                                 const uint8_t *pri_key, uint16_t pri_key_len,
                                 uint8_t *output_buf, uint16_t output_buf_len, 
                                 uint16_t *output_len);

#endif // SIGN_ON_BASIC_ECC_256_SEC_H