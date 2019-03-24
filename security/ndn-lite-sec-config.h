/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_SEC_CONFIG_H
#define NDN_LITE_SEC_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Here you can define the security backend to use for various security
 * functionality of ndn-lite. this is useful if you experience issues
 * with security library conflicts in the development environment you
 * are using.
 */

/**
 * Selecting Backend
 */
/**
 * The default software backend provided by NDN-Lite
 * CFLAG += -DNDN_LITE_SEC_BACKEND_DEFAULT
 *
 * NOTE: If you select this backend, you will have to use an
 *       rng function other than ndn_lite_rng; other backends, such as
 *       NDN_LITE_SEC_BACKEND_NRF_CRYPTO, will automatically
 *       assign a function to ndn_lite_rng.
 */
#if defined NDN_LITE_SEC_BACKEND_DEFAULT

  // SHA256 backend
  #ifndef NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
    #define NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
  #endif
  // RNG backend
  #ifndef NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
    #define NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
  #endif
  // AES backend
  #ifndef NDN_LITE_SEC_BACKEND_AES_DEFAULT
    #define NDN_LITE_SEC_BACKEND_AES_DEFAULT
  #endif
  // ECC backend
  #ifndef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
    #define NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  #endif
  // HMAC backend
  #ifndef NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
    #define NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
  #endif

/**
 * The Nordic SDK NRF Crypto backend
 * CFLAG += -DNDN_LITE_SEC_BACKEND_NRF_CRYPTO
 */
#elif defined NDN_LITE_SEC_BACKEND_NRF_CRYPTO

  // SHA256 backend
  #ifndef NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
    #define NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
  #endif
  // RNG backend
  #ifndef NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO
    #define NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO
  #endif
  // AES backend
  #ifndef NDN_LITE_SEC_BACKEND_AES_DEFAULT
    #define NDN_LITE_SEC_BACKEND_AES_DEFAULT
  #endif
  // ECC backend
  #ifndef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
    #define NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  #endif
  // HMAC backend
  #ifndef NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
    #define NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
  #endif


/**
 * The default software backend provided by NDN-Lite
 */
#else

  #define NDN_LITE_SEC_BACKEND_DEFAULT
  // SHA256 backend
  #ifndef NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
    #define NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
  #endif
  // RNG backend
  #ifndef NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
    #define NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
  #endif
  // AES backend
  #ifndef NDN_LITE_SEC_BACKEND_AES_DEFAULT
    #define NDN_LITE_SEC_BACKEND_AES_DEFAULT
  #endif
  // ECC backend
  #ifndef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
    #define NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  #endif
  // HMAC backend
  #ifndef NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
    #define NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
  #endif

#endif /* NDN_LITE_SEC_BACKEND_DEFAULT || NDN_LITE_SEC_BACKEND_NRF_CRYPTO */


/**
 * Including corresponding header files
 */
// SHA256 backend
#if defined NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
  #include "detail/default-backend/ndn-lite-default-sha-impl.h"
#endif // NDN_LITE_SEC_BACKEND_SHA256_DEFAULT

// RNG backend
#if defined NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
// do nothing
#endif // NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT

// AES backend
#if defined NDN_LITE_SEC_BACKEND_AES_DEFAULT
  #include "detail/default-backend/ndn-lite-default-aes-impl.h"
#endif // NDN_LITE_SEC_BACKEND_AES_DEFAULT

// ECC backend
#if defined NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  #include "detail/default-backend/ndn-lite-default-ecc-impl.h"
#endif // NDN_LITE_SEC_BACKEND_ECC_DEFAULT

// HMAC backend
#if defined NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
  #include "detail/default-backend/ndn-lite-default-hmac-impl.h"
#endif

void
register_platform_security_init(void (*init)(void));

void
ndn_security_init(void);

#ifdef __cplusplus
};
#endif

#endif // NDN_LITE_SEC_CONFIG_H
