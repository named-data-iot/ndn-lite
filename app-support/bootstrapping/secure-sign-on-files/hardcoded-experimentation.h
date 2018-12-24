/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef HARDCODED_EXPERIMENTATION_H
#define HARDCODED_EXPERIMENTATION_H

#include "secure-sign-on/variants/basic/sign-on-basic-client-consts.h"
#include "secure-sign-on/variants/basic/variants/ecc_256/sign-on-basic-ecc-256-consts.h"

#include <stdint.h>

extern const uint8_t DEVICE_IDENTIFIER[SIGN_ON_BASIC_CLIENT_DEVICE_IDENTIFIER_MAX_LENGTH];

extern const uint8_t DEVICE_CAPABILITIES[SIGN_ON_BASIC_CLIENT_DEVICE_CAPABILITIES_MAX_LENGTH];

// these are the raw 32 bytes of the bootstrapping ecc private key
extern const uint8_t BOOTSTRAP_ECC_PRIVATE[32];

// these are the ASN encoded bytes of the bootstrapping ecc public key;
// this means there are 27 bytes prepended to the raw public key bytes which
// represent an ASN header, and the last 64 bytes of this array are the
// actual raw public key bytes
extern const uint8_t BOOTSTRAP_ECC_PUBLIC_ASN_ENCODED[91];

// these are the raw key bytes of the ecc public key (including)
// the point identifier, which is the first byte
extern const uint8_t BOOTSTRAP_ECC_PUBLIC[65];

extern const uint8_t BOOTSTRAP_ECC_PUBLIC_NO_POINT_IDENTIFIER[64];

extern const uint8_t SECURE_SIGN_ON_CODE[SIGN_ON_BASIC_ECC_256_SECURE_SIGN_ON_CODE_LENGTH];

#endif // HARDCODED_EXPERIMENTATION_H