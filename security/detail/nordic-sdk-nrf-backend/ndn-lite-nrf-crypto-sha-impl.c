/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-lite-nrf-crypto-sha-impl.h"
#include "../../ndn-lite-sha.h"
#include "../../../ndn-error-code.h"

// Includes from the "hash" example of the SDK
//**************************************//
#include "boards.h"
#include "nrf_assert.h"
#include "nrf_crypto.h"
#include "nrf_crypto_hash.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
//**************************************//

int
ndn_lite_nrf_crypto_sha256(const uint8_t *payload, uint16_t payload_len, uint8_t *output)
{
  // taken from the "hash" example of the SDK
  //**************************************//
  nrf_crypto_hash_sha256_digest_t ext_digest;
  const uint16_t ext_digest_len = NRF_CRYPTO_HASH_SIZE_SHA256;

  nrf_crypto_hash_context_t ext_hash_context;

  //**************************************//

  // need to calculate N2 pub digest here
  // taken from the "hash" example of the SDK
  //**************************************//
  //  // Integrated version
  ret_code_t err_code;
  uint16_t current_digest_len = ext_digest_len;
  err_code = nrf_crypto_hash_calculate(&ext_hash_context,              // Context or NULL to allocate internally
                                       &g_nrf_crypto_hash_sha256_info, // Info structure configures hash mode
                                       payload,                        // Input buffer
                                       payload_len,                    // Input size
                                       ext_digest,                     // Result buffer
                                       &current_digest_len);           // Result size
  if (err_code != NRF_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;

  //**************************************//
  memcpy(output, ext_digest, current_digest_len);

  return NDN_SUCCESS;
}

void
ndn_lite_nrf_crypto_sha_load_backend(void)
{
  ndn_sha_backend_t* backend = ndn_sha_get_backend();
  backend->sha256 = ndn_lite_nrf_crypto_sha256;
}
