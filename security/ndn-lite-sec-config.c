/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-sec-config.h"

void
ndn_security_init(void)
{
  // SHA256 backend
#if defined NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
  ndn_lite_default_sha_load_backend();
#elif defined NDN_LITE_SEC_BACKEND_SHA256_NRF_CRYPTO
  ndn_lite_nrf_crypto_sha_load_backend();
#endif // NDN_LITE_SEC_BACKEND_SHA256_DEFAULT || NDN_LITE_SEC_BACKEND_SHA256_NRF_CRYPTO

  // RNG backend
#if defined NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
// do nothing
#elif defined NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO
  ndn_lite_nrf_crypto_rng_load_backend();
#endif // NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT || NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO

  // AES backend
#if defined NDN_LITE_SEC_BACKEND_AES_DEFAULT
  ndn_lite_default_aes_load_backend();
#endif // NDN_LITE_SEC_BACKEND_AES_DEFAULT

  // ECC backend
#if defined NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  ndn_lite_default_ecc_load_backend();
#endif // NDN_LITE_SEC_BACKEND_ECC_DEFAULT

  // HMAC backend
#if defined NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
  ndn_lite_default_hmac_load_backend();
#endif
}
