/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-sec-config.h"

void (*platform_security_init)(void) = NULL;

void
register_platform_security_init(void (*init)(void)) {
  platform_security_init = init;
}

void
ndn_security_init(void)
{
  // SHA256 backend
#if defined NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
  ndn_lite_default_sha_load_backend();
#endif // NDN_LITE_SEC_BACKEND_SHA256_DEFAULT

  // RNG backend
#if defined NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
// do nothing
#endif // NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT

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

  if (platform_security_init != NULL) {
    platform_security_init();
  }

}
