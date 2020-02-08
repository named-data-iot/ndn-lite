/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENUMS_H
#define NDN_ENUMS_H

// face state
enum {
  NDN_FACE_STATE_DOWN = 0,
  NDN_FACE_STATE_UP = 1,
  NDN_FACE_STATE_DESTROYED = 2,
};

// face type
enum {
  NDN_FACE_TYPE_UNDEFINED = 0,
  NDN_FACE_TYPE_APP = 1,
  NDN_FACE_TYPE_NET = 2,
};

// forward strategy
enum {
  NDN_FWD_STRATEGY_SUPPRESS = 0,
  NDN_FWD_STRATEGY_MULTICAST = 1,
};

// content type values
enum {
  NDN_CONTENT_TYPE_BLOB = 0,
  NDN_CONTENT_TYPE_LINK = 1,
  NDN_CONTENT_TYPE_KEY  = 2,
  NDN_CONTENT_TYPE_NACK = 3,
  NDN_CONTENT_TYPE_CCM  = 50,
};

// signature type values
enum {
  NDN_SIG_TYPE_DIGEST_SHA256 = 0,
  NDN_SIG_TYPE_ECDSA_SHA256  = 3,
  NDN_SIG_TYPE_HMAC_SHA256   = 4,
  NDN_SIG_TYPE_RSA_SHA256    = 1,
};

// ecdsa curve type
enum {
  NDN_ECDSA_CURVE_SECP160R1 = 21,
  NDN_ECDSA_CURVE_SECP192R1 = 24,
  NDN_ECDSA_CURVE_SECP224R1 = 28,
  NDN_ECDSA_CURVE_SECP256R1 = 32,
  NDN_ECDSA_CURVE_SECP256K1 = 33,
};

// access control key type
enum {
  NDN_AC_EK = 0,
  NDN_AC_DK = 1,
};

// asn encoding
enum {
  ASN1_SEQUENCE = 0x30,
  ASN1_INTEGER  = 0x02,
};

#endif // NDN_ENUMS_H
