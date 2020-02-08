/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_LITE_SEC_CONFIG_H
#define NDN_LITE_SEC_CONFIG_H

#include "default-backend/ndn-lite-default-sha-impl.h"
#include "default-backend/ndn-lite-default-aes-impl.h"
#include "default-backend/ndn-lite-default-ecc-impl.h"
#include "default-backend/ndn-lite-default-hmac-impl.h"
#include "default-backend/ndn-lite-default-rng-impl.h"

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
 * In this function, developers can load their own crypto backend.
 * To load a backend:
 * Step 1: include the front-end header file, e.g., ndn-lite/security/ndn-lite-hmac.h
 * Step 2: in your init function, get the backend by invoking the get_backend function, e.g., ndn_hmac_get_backend()
 * Step 3: assign platform-specific functions to the function pointers of the backend struct
 * Step 4: pass this function as a param to register_platform_security_init.
 * If you have multiple backends to load, simply put all the loading steps into one init function.
 * @param init. Input. A pointer to the function which will load platform-specific backends.
 */
void
register_platform_security_init(void (*init)(void));

/**
 * The ndn_security_init function will automatically load NDN-Lite's default backend,
 * which contains a SHA256 backend, an AES backend, an ECC backend, and a HMAC backend.
 * IMPORTANT: the default NDN-Lite crypto backend does not support a RNG backend.
 *
 * If register_platform_security_init is invoked before ndn_security_init, the init function
 * will be invoked to replace the default backend with platform-specific backends.
 */
void
ndn_security_init(void);

#ifdef __cplusplus
};
#endif

#endif // NDN_LITE_SEC_CONFIG_H
