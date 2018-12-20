/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "hmac-nrf-crypto-impl.h"

#include "../../sign-on-basic-sec-consts.h"
#include "../../../../../../../../../adaptation/ndn-nrf-ble-adaptation/logger.h"

bool sign_on_basic_nrf_crypto_vrfy_hmac_sha256_sig(const uint8_t *payload, uint16_t payload_len,
    const uint8_t *sig, uint16_t sig_len,
    const uint8_t *key, uint16_t key_len_in) {

  // taken from the "hmac" example of the SDK
  //******************************************************//
  nrf_crypto_hash_sha256_digest_t m_digest;
  static uint8_t m_data[] = {0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65};
  static uint8_t m_key[] = {0x6b, 0x65, 0x79};
  //static uint8_t m_digest[NRF_CRYPTO_HASH_SIZE_SHA256] = {0};
  static nrf_crypto_hmac_context_t m_context;

  static uint8_t m_expected_digest[NRF_CRYPTO_HASH_SIZE_SHA256] =
      {
          0x6e, 0x9e, 0xf2, 0x9b, 0x75, 0xff, 0xfc, 0x5b, 0x7a, 0xba, 0xe5, 0x27, 0xd5, 0x8f, 0xda, 0xdb,
          0x2f, 0xe4, 0x2e, 0x72, 0x19, 0x01, 0x19, 0x76, 0x91, 0x73, 0x43, 0x06, 0x5f, 0x58, 0xed, 0x4a};

  //******************************************************//

  // taken from the "hmac" example of the SDK"
  //*****************************************************//

  size_t digest_len = sizeof(m_digest);
  size_t key_len = key_len_in;

  APP_LOG("HMAC example started.\n");

  // Initialize frontend (which also initializes backend).
  ret_code_t err_code = nrf_crypto_hmac_init(
      &m_context,
      &g_nrf_crypto_hmac_sha256_info,
      key,
      key_len);
  if (err_code != NRF_SUCCESS)
    return SEC_OP_FAILURE;

  // Push all data in one go (could be done repeatedly)
  err_code = nrf_crypto_hmac_update(&m_context, payload, payload_len);
  if (err_code != NRF_SUCCESS)
    return SEC_OP_FAILURE;

  // Finish calculation
  err_code = nrf_crypto_hmac_finalize(&m_context, m_digest, &digest_len);
  if (err_code != NRF_SUCCESS)
    return SEC_OP_FAILURE;

  // Print digest (result).
  APP_LOG_HEX("Calculated HMAC:", m_digest, digest_len);

  if (memcmp(m_digest, sig, sig_len) != 0) {
    APP_LOG("Failed to verify bootstrapping request response by secure sign on code.\n");
    return SEC_OP_FAILURE;
  }

  //*****************************************************//

  return SEC_OP_SUCCESS;
}