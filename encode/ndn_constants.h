/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_NDN_CONSTANTS_H
#define NDN_ENCODING_NDN_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

// buffer and block memory allocation
#define NAME_COMPONENT_BUFFER_SIZE 72
#define NAME_COMPONENT_BLOCK_SIZE 74
#define NDN_NAME_COMPONENTS_SIZE 12
#define NDN_NAME_BLOCK_SIZE 891
#define NDN_AES_BLOCK_SIZE 16

#define NDN_INTEREST_PARAMS_BUFFER_SIZE 256
#define NDN_CONTENT_BUFFER_SIZE 256
#define NDN_SIGNATURE_BUFFER_SIZE 128

#define NDN_FIB_MAX_SIZE 20
#define NDN_PIT_MAX_SIZE 128
#define NDN_CS_MAX_SIZE 10
#define NDN_FACE_TABLE_MAX_SIZE 10

// default values
#define DEFAULT_INTEREST_LIFETIME 4000

// error messages
#define NDN_ERROR_OVERSIZE -10
#define NDN_ERROR_NAME_INVALID_FORMAT -11
#define NDN_ERROR_WRONG_TLV_TYPE -12
#define NDN_ERROR_OVERSIZE_VAR -13

#define NDN_ERROR_WRONG_KEY_SIZE -22
#define NDN_ERROR_WRONG_SIG_SIZE -23
#define NDN_ERROR_NOT_ENABLED_FEATURE -24
#define NDN_ERROR_CRYPTO_ALGO_FAILURE -25
#define NDN_ERROR_UNSUPPORT_CRYPTO_ALGO -26
#define NDN_ERROR_UNSUPPORT_SIGN_TYPE -26


// flag messages
#define NDN_FLAG_WHEN_ENCODING -30
#define NDN_FLAG_WHEN_DECODING -31

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
  NDN_SIG_TYPE_RSA_SHA256   = 1,
};

// ecdsa curve type
enum {
  NDN_ECDSA_CURVE_SECP160R1 = 20,
  NDN_ECDSA_CURVE_SECP192R1 = 24,
  NDN_ECDSA_CURVE_SECP224R1 = 28,
  NDN_ECDSA_CURVE_SECP256R1 = 32,
  NDN_ECDSA_CURVE_SECP256K1 = 33,
};

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_NDN_CONSTANTS_H
