/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sign-on-basic-ecc-256-sec.h"

#include "../../../../ndn-constants.h"

#include "../../security/sign-on-basic-sec-consts.h"
#include "../../security/sign-on-basic-sec-impl.h"

int sign_on_basic_ecc_256_gen_sha256_hash(const uint8_t *payload, uint32_t payload_len, uint8_t *output) {

  return sign_on_basic_gen_sha256_hash(payload, payload_len, output);

}

int sign_on_basic_ecc_256_decrypt_kd_pri(uint8_t *key, uint32_t key_len, const uint8_t *encrypted_kd_pri, 
                                                       uint32_t encrypted_kd_pri_len, 
                                                       uint8_t *decrypted_kd_pri, uint32_t decrypted_kd_pri_buf_len,
                                                       uint32_t *decrypted_kd_pri_len) {
  int ret_val = sign_on_basic_aes_cbc_decrypt(key, key_len,
                                                       encrypted_kd_pri, encrypted_kd_pri_len, 
                                                       decrypted_kd_pri, decrypted_kd_pri_buf_len);

  // set the decrypted_kd_pri_len to the size of a raw secp_256r1 private key
  *decrypted_kd_pri_len = SIGN_ON_BASIC_ECC_CURVE_SECP_256R1_RAW_PRI_KEY_LENGTH;

  return ret_val;

}

int sign_on_basic_ecc_256_vrfy_btstrp_rqst_rspns_sig(const uint8_t *payload, uint32_t payload_len,
                                                                const uint8_t *sig, uint32_t sig_len,
                                                                const uint8_t *key, uint32_t key_len) {
  return sign_on_basic_vrfy_hmac_sha256_sig(payload, payload_len, sig, sig_len,
                                                           key, key_len);
}

int sign_on_basic_ecc_256_vrfy_cert_rqst_rspns_sig(const uint8_t *payload, uint32_t payload_len,
                                                                const uint8_t *sig, uint32_t sig_len,
                                                                const uint8_t *key, uint32_t key_len) {
  return sign_on_basic_vrfy_hmac_sha256_sig(payload, payload_len, sig, sig_len,
                                                           key, key_len);
}

int sign_on_basic_ecc_256_gen_btstrp_rqst_sig(const uint8_t *pri_key,
                                              const uint8_t *payload, uint32_t payload_len,
                                              uint8_t *output_buf, uint32_t output_buf_len,
                                              uint32_t *output_len) {
  return sign_on_basic_gen_sha256_ecdsa_sig(
                     pri_key, 
                     uECC_secp256r1(),
                     payload, payload_len, output_buf,
                     output_buf_len, output_len);
}

int sign_on_basic_ecc_256_gen_cert_rqst_sig(const uint8_t *pri_key,
                                            const uint8_t *payload, uint32_t payload_len,
                                            uint8_t *output_buf, uint32_t output_buf_len,
                                            uint32_t *output_len) {
  return sign_on_basic_gen_sha256_ecdsa_sig(
                     pri_key, 
                     uECC_secp256r1(),
                     payload, payload_len, output_buf,
                     output_buf_len, output_len);
}

int sign_on_basic_ecc_256_gen_fin_msg_sig(const uint8_t *pri_key,
                                          const uint8_t *payload, uint32_t payload_len,
                                          uint8_t *output_buf, uint32_t output_buf_len,
                                          uint32_t *output_len) {
  return sign_on_basic_gen_sha256_ecdsa_sig(
                     pri_key, 
                     uECC_secp256r1(), 
                     payload, payload_len, output_buf,
                     output_buf_len, output_len);
}

int sign_on_basic_ecc_256_gen_n1_keypair(uint8_t *pub_key_buf, uint32_t pub_key_buf_len, 
                                         uint32_t *pub_key_output_len,
                                         uint8_t *pri_key_buf, uint32_t pri_key_buf_len, 
                                         uint32_t *pri_key_output_len) {
  return sign_on_basic_gen_ec_keypair(pub_key_buf, pub_key_buf_len,
                                                 pub_key_output_len,
                                                 pri_key_buf, pri_key_buf_len,
                                                 pri_key_output_len,
                                                 uECC_secp256r1());
}

int sign_on_basic_ecc_256_gen_kt(const uint8_t *pub_key, uint32_t pub_key_len,
                                 const uint8_t *pri_key, uint32_t pri_key_len,
                                 uint8_t *output_buf, uint32_t output_buf_len, 
                                 uint32_t *output_len) {
  return sign_on_basic_gen_ecdh_shared_secret(pub_key, pub_key_len,
                                                         pri_key, pri_key_len,
                                                         uECC_secp256r1(),
                                                         output_buf, output_buf_len,
                                                         output_len);
}
