/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-lite-aes-nrf-crypto-impl.h"

#include "../../../ndn-error-code.h"

int ndn_lite_nrf_crypto_decrypt_aes_cbc_pkcs5pad(uint8_t *key, uint16_t key_len, 
    const uint8_t *encrypted_payload, uint16_t encrypted_payload_len,
    uint8_t *decrypted_payload, uint16_t *decrypted_payload_len) {

  uint8_t iv[16];
  ret_code_t ret_val;
  uint16_t len_in;
  uint16_t len_out;

  static char encrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];
  static char decrypted_text[NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE];

  static nrf_crypto_aes_context_t cbc_decr_128_ctx; // AES CBC decryption context

  memset(encrypted_text, 0, sizeof(encrypted_text));
  memset(decrypted_text, 0, sizeof(decrypted_text));

  int max_key_length = 16;

  /* Init decryption context for 128 bit key and PKCS7 padding mode */
  ret_val = nrf_crypto_aes_init(&cbc_decr_128_ctx,
      &g_nrf_crypto_aes_cbc_128_info,
      NRF_CRYPTO_DECRYPT);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }

  /* Set key for decryption context - only first 128 key bits will be used */
  ret_val = nrf_crypto_aes_key_set(&cbc_decr_128_ctx, key);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }

  memset(iv, 0, sizeof(iv));
  /* Set IV for decryption context */

  ret_val = nrf_crypto_aes_iv_set(&cbc_decr_128_ctx, iv);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }

  memcpy(encrypted_text, encrypted_payload, encrypted_payload_len);
  len_out = encrypted_payload_len;

  //APP_LOG_HEX("Bytes we are attempting to decrypt", encrypted_text, len_out);
  //APP_LOG("Length of bytes we are attempting to decrypt: %d\n", len_out);
  //APP_LOG_HEX("Attempting to decrypt with this key", key, max_key_length);

  /* Decrypt text */
  ret_val = nrf_crypto_aes_finalize(&cbc_decr_128_ctx,
      (uint8_t *)encrypted_text,
      //encrypted_payload,
      len_out,
      //encrypted_payload_len,
      (uint8_t *)decrypted_text,
      //decrypted_payload,
      &len_out);
      //decrypted_payload_len);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  //APP_LOG("Length of decrypted contents: %d\n", len_out);

  memcpy(decrypted_payload, decrypted_text, len_out);
  *decrypted_payload_len = len_out;

  return NDN_SUCCESS;

  /* trim padding */
  //decrypted_text[len_out] = '\0';
}