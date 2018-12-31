/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sec-impl.h"

#ifdef nRF52840
  #include "detail-sha256/sha256-nrf-crypto-impl.h"
  #include "detail-aes/aes-nrf-crypto-impl.h"
  #include "detail-hmac/hmac-nrf-crypto-impl.h"
  #include "detail-ecc/ecc-nrf-crypto-impl.h"
  #include "detail-ecc/ecc-microecc-impl.h"
#endif

int sign_on_basic_gen_sha256_hash(const uint8_t *payload, uint16_t payload_len, uint8_t *output) {
  #ifdef nRF52840
    return sign_on_basic_nrf_crypto_gen_sha256_hash(payload, payload_len, output);
  #endif
}

int sign_on_basic_decrypt_aes_cbc_pkcs5pad(uint8_t *key, uint16_t key_len, 
                                           const uint8_t *encrypted_payload, uint16_t encrypted_payload_len,
                                           uint8_t *decrypted_payload, uint16_t *decrypted_payload_len) {
  #ifdef nRF52840
  return sign_on_basic_nrf_crypto_decrypt_aes_cbc_pkcs5pad(key, key_len, encrypted_payload,
                                                           encrypted_payload_len, decrypted_payload,
                                                           decrypted_payload_len);
  #endif
}

int sign_on_basic_vrfy_hmac_sha256_sig(const uint8_t *payload, uint16_t payload_len,
                                       const uint8_t *sig, uint16_t sig_len,
                                       const uint8_t *key, uint16_t key_len) {
  #ifdef nRF52840
  return sign_on_basic_nrf_crypto_vrfy_hmac_sha256_sig(payload, payload_len, sig, sig_len,
                                                       key, key_len);
  #endif
}

int sign_on_basic_gen_sha256_ecdsa_sig(const uint8_t *pri_key_raw,
                                       const uint8_t *payload, uint16_t payload_len,
                                       uint8_t *output_buf, uint16_t output_buf_len, 
                                       uint16_t *output_len) {
  #ifdef nRF52840
  return sign_on_basic_microecc_gen_sha256_ecdsa_sig(pri_key_raw, payload, payload_len,
                                                     output_buf, output_buf_len, output_len);
  #endif
}

int sign_on_basic_gen_ecdh_shared_secret(const uint8_t *pub_key_raw, uint16_t pub_key_raw_len,
                                         const uint8_t *pri_key_raw, uint16_t pri_key_raw_len,
                                         uECC_Curve curve,
                                         uint8_t *output_buf, uint16_t output_buf_len, 
                                         uint16_t *output_len) {
  #ifdef nRF52840
  return sign_on_basic_nrf_crypto_gen_ecdh_shared_secret(pub_key_raw, pub_key_raw_len,
                                                         pri_key_raw, pri_key_raw_len,
                                                         curve,
                                                         output_buf, output_buf_len,
                                                         output_len);
  #endif
}

int sign_on_basic_gen_ec_keypair(uint8_t *pub_key_buf, uint16_t pub_key_buf_len, 
                                 uint16_t *pub_key_output_len,
                                 uint8_t *pri_key_buf, uint16_t pri_key_buf_len, 
                                 uint16_t *pri_key_output_len,
                                 uECC_Curve curve) {
  #ifdef nRF52840
  return sign_on_basic_nrf_crypto_gen_ec_keypair(pub_key_buf, pub_key_buf_len,
                                                 pub_key_output_len,
                                                 pri_key_buf, pri_key_buf_len,
                                                 pri_key_output_len,
                                                 curve);
  #endif
}