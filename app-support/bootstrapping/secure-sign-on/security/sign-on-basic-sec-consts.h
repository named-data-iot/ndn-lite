/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_SEC_CONSTS_H
#define SIGN_ON_BASIC_SEC_CONSTS_H

#define SIGN_ON_BASIC_SEC_OP_FAILURE 0 ///< Implementations of the generic security interfaces of sign_on_basic_client.h should return this for a successful operation
#define SIGN_ON_BASIC_SEC_OP_SUCCESS 1 ///< Implementations of the generic security interfaces of sign_on_basic_client.h should return this for a failed operation

#define SIGN_ON_BASIC_SHA256_HASH_SIZE 32 ///< Length of SHA256 hash

#define SIGN_ON_BASIC_ECC_CURVE_SECP_256R1_RAW_PRI_KEY_LENGTH 32 ///< SECP_256R1 ECC curve private key length
#define SIGN_ON_BASIC_ECC_CURVE_SECP_256R1_RAW_PUB_KEY_LENGTH 64 ///< SECP_256R1 ECC curve public key length, no point identifier

#define SIGN_ON_BASIC_AES_KEY_MAX_LENGTH 16 ///< For encryption and decryption, only this many bytes of any keys will be used.

/** @defgroup ECC curve types
 * @{ */
#define SIGN_ON_BASIC_ECC_CURVE_SECP_256R1 0 ///< Indicates to use SECP_256R1 ECC curve
/** @} */


#endif // SIGN_ON_BASIC_SEC_CONSTS_H