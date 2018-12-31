
#include "../ndn-lite-sec-config.h"

#ifdef NDN_LITE_SEC_BACKEND_AES_NRF_CRYPTO

#include "../aes.h"

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_drv_clock.h"

#include "nrf_drv_power.h"

#include "app_error.h"
#include "app_util.h"

#include "boards.h"

#include "mem_manager.h"
#include "nrf_crypto.h"
#include "nrf_crypto_error.h"

int
ndn_aes_cbc_encrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv,
                    const uint8_t* key_value, uint8_t key_size)
{
  if (input_size + NRF_CRYPTO_AES_BLOCK_SIZE > output_size || key_size < 16) {
    return NDN_SEC_WRONG_AES_SIZE;
  }

  ret_code_t ret_val;

  static nrf_crypto_aes_context_t cbc_encr_128_ctx; // AES CBC encryption context

  /* Init encryption context for 128 bit key and PKCS7 padding mode */
  ret_val = nrf_crypto_aes_init(&cbc_encr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_info,
                                  NRF_CRYPTO_ENCRYPT);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_AES_INIT_FAILED;
  }

  /* Set key for encryption context - only first 128 key bits will be used */
  ret_val = nrf_crypto_aes_key_set(&cbc_encr_128_ctx, key_value);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_AES_INIT_FAILED;
  }

  ret_val = nrf_crypto_aes_iv_set(&cbc_encr_128_ctx, aes_iv);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_AES_INIT_FAILED;
  }

  /* Encrypt text
     When padding is selected m_encrypted_text buffer shall be at least 16 bytes larger
     than text_len. */
  size_t len_in = (size_t) input_size;
  size_t len_out;
  ret_val = nrf_crypto_aes_finalize(&cbc_encr_128_ctx,
                                    input_value,
                                    len_in,
                                    (uint8_t *)output_value,
                                    &len_out);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_AES_FINALIZE_FAILED;
  }

  return 0;
}

int
ndn_aes_cbc_decrypt(const uint8_t* input_value, uint8_t input_size,
                    uint8_t* output_value, uint8_t output_size,
                    const uint8_t* aes_iv,
                    const uint8_t* key_value, uint8_t key_size)
{
  if (output_size < input_size - NRF_CRYPTO_AES_BLOCK_SIZE || key_size < 16) {
    return NDN_SEC_WRONG_AES_SIZE;
  }

  ret_code_t ret_val;

  static nrf_crypto_aes_context_t cbc_decr_128_ctx; // AES CBC decryption context

  /* Init decryption context for 128 bit key and PKCS7 padding mode */
  ret_val = nrf_crypto_aes_init(&cbc_decr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_info,
                                  NRF_CRYPTO_DECRYPT);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_AES_INIT_FAILED;
  }


  /* Set key for decryption context - only first 128 key bits will be used */
  ret_val = nrf_crypto_aes_key_set(&cbc_decr_128_ctx, key_value);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_AES_INIT_FAILED;
  }

  /* Set IV for decryption context */
  ret_val = nrf_crypto_aes_iv_set(&cbc_decr_128_ctx, aes_iv);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_AES_INIT_FAILED;
  }

  /* Decrypt text */
  size_t len_in = (size_t) input_size;
  size_t len_out;
  ret_val = nrf_crypto_aes_finalize(&cbc_decr_128_ctx,
                                    input_value,
                                    len_in,
                                    output_value,
                                    &len_out);
  if (ret_val != NRF_SUCCESS) {
    return NDN_SEC_AES_FINALIZE_FAILED;
  }

  return 0;
}

#endif // NDN_LITE_SEC_BACKEND_AES_NRF_CRYPTO