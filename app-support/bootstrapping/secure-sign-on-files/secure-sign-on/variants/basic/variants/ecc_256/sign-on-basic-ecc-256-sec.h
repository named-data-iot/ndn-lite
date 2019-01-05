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

/**@brief Generate a sha256 hash.
 */
int sign_on_basic_ecc_256_gen_sha256_hash(const uint8_t *payload, uint32_t payload_len, uint8_t *output);

/**@brief The KD key pair private key should be encrypted using AES CBC with PCS5 padding.
 *
 * @param[in] key The format of key should be the same format used and generated in the 
 *                  micro-ecc library.
 *          The unecrypted KD key pair private key should be in the same format generated 
 *          and used in the micro-ecc library.
 */
int sign_on_basic_ecc_256_decrypt_kd_pri(uint8_t *key, uint32_t key_len, const uint8_t *encrypted_payload, 
                                         uint32_t encrypted_payload_len, uint8_t *decrypted_payload,
                                         uint32_t decrypted_payload_buf_len, 
                                         uint32_t *decrypted_payload_len);

/**@brief The bootstrapping request response signature should be an hmac sha256 signature.
 *
 * @param[in] key The format of key should be the same format used and generated in the 
 *                  micro-ecc library.
 */
int sign_on_basic_ecc_256_vrfy_btstrp_rqst_rspns_sig(const uint8_t *payload, uint32_t payload_len,
                                                     const uint8_t *sig, uint32_t sig_len,
                                                     const uint8_t *key, uint32_t key_len);

/**@brief The certificate request response signature should be an hmac sha256 signature.
 *
 * @param[in] key The format of key should be the same format used and generated in the 
 *                  micro-ecc library.
 *          
 */
int sign_on_basic_ecc_256_vrfy_cert_rqst_rspns_sig(const uint8_t *payload, uint32_t payload_len,
                                                   const uint8_t *sig, uint32_t sig_len,
                                                   const uint8_t *key, uint32_t key_len);

/**@brief The certificate request signature should be an ecdsa sha256 signature.
 *
 * @param[in] pri_key  The format of pri_key should be the same format used and generated in the 
 *                       micro-ecc library.
 *
 */
int sign_on_basic_ecc_256_gen_cert_rqst_sig(const uint8_t *pri_key,
                                            const uint8_t *payload, uint32_t payload_len,
                                            uint8_t *output_buf, uint32_t output_buf_len,
                                            uint32_t *output_len);

/**@brief The bootstrapping request signature should be an ecdsa sha256 signature.
 *
 * @param[in] pri_key  The format of pri_key should be the same format used and generated in the 
 *                       micro-ecc library.
 *          
 */
int sign_on_basic_ecc_256_gen_btstrp_rqst_sig(const uint8_t *pri_key,
                                              const uint8_t *payload, uint32_t payload_len,
                                              uint8_t *output_buf, uint32_t output_buf_len,
                                              uint32_t *output_len);

/**@brief The finish message signature should be an ecdsa sha256 signature.
 *
 * @param[in] pri_key  The format of pri_key should be the same format used and generated in the 
 *                       micro-ecc library.
 */
int sign_on_basic_ecc_256_gen_fin_msg_sig(const uint8_t *pri_key,
                                          const uint8_t *payload, uint32_t payload_len,
                                          uint8_t *output_buf, uint32_t output_buf_len,
                                          uint32_t *output_len);

/**@brief The N1 key pair should be a pair of ecc keys, based on the "secp256r1" curve.
 *
 * @param[in] pub_key_buf  The format of the public key should be the same format used and
 *                           generated in the micro-ecc library.
 * @param[in] pri_key_buf  The format of the private key should be the same format used and
 *                           generated in the micro-ecc library.
 */
int sign_on_basic_ecc_256_gen_n1_keypair(uint8_t *pub_key_buf, uint32_t pub_key_buf_len, 
                                         uint32_t *pub_key_output_len,
                                         uint8_t *pri_key_buf, uint32_t pri_key_buf_len, 
                                         uint32_t *pri_key_output_len);

/**@brief The keys used to generate KT should be ecc keys, based on the "secp256r1" curve.
 *
 * @param[in] pub_key      The format of the public key should be the same format used and
 *                           generated in the micro-ecc library.
 * @param[in] pri_key      The format of the private key should be the same format used and
 *                           generated in the micro-ecc library.
 */
int sign_on_basic_ecc_256_gen_kt(const uint8_t *pub_key, uint32_t pub_key_len,
                                 const uint8_t *pri_key, uint32_t pri_key_len,
                                 uint8_t *output_buf, uint32_t output_buf_len, 
                                 uint32_t *output_len);

#endif // SIGN_ON_BASIC_ECC_256_SEC_H