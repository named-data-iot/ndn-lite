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
#include "../../../adaptation/ndn-nrf-ble-adaptation/logger.h"
#include "../../../../ndn-error-code.h"
#include "../../../../ndn-constants.h"

int ndn_lite_aes_cbc_decrypt_nrf_crypto(const uint8_t* input_value, uint8_t input_size,
                                    uint8_t* output_value, uint8_t output_size,
                                    const uint8_t* aes_iv,
                                    const uint8_t* key_value, uint8_t key_size) {

  if (input_size + NRF_CRYPTO_AES_BLOCK_SIZE > output_size || key_size < NDN_SEC_AES_MIN_KEY_SIZE) {
    return NDN_SEC_WRONG_AES_SIZE;
  }

  ret_code_t ret_val;

  static nrf_crypto_aes_context_t cbc_decr_128_ctx; // AES CBC decryption context

  /* Init decryption context for 128 bit key and PKCS7 padding mode */
  ret_val = nrf_crypto_aes_init(&cbc_decr_128_ctx,
                                &g_nrf_crypto_aes_cbc_128_info,
                                NRF_CRYPTO_DECRYPT);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }

  /* Set key for decryption context - only first 128 key bits will be used */
  ret_val = nrf_crypto_aes_key_set(&cbc_decr_128_ctx, key_value);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }

  /* Set IV for decryption context */
  ret_val = nrf_crypto_aes_iv_set(&cbc_decr_128_ctx, aes_iv);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }

  APP_LOG_HEX("Bytes we are attempting to decrypt", input_value, input_size);
  APP_LOG("Length of bytes we are attempting to decrypt: %d\n", input_size);
  APP_LOG_HEX("Attempting to decrypt with this key", key_value, NDN_SEC_AES_MIN_KEY_SIZE);

  size_t len_out;
  /* Decrypt text */
  ret_val = nrf_crypto_aes_finalize(&cbc_decr_128_ctx,
      input_value,
      input_size,
      output_value,
      &len_out);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  APP_LOG("Length of decrypted contents: %d\n", len_out);

  output_size = input_size;

  return NDN_SUCCESS;
}