/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_ECC_256_CONSTS_H
#define SIGN_ON_BASIC_ECC_256_CONSTS_H

// I will just put a description of the ECC_256 variant of the sign-on protocol below:
//
//The main variance in the sign-on protocol comes from the different possible security implementations.
//This is reflected in how there is a generic security interface in the sign-on-basic-client.h file,
//which can be changed out for different backend implementations depending on the variant that is
//selected and the security libraries that are available on whatever system the sign-on protocol is being
//run on.
//
//The ways in which the sign-on protocol can vary in terms of the security implementation is summarized
//within the sign_on_basic_sec_intf object in sign-on-basic-client.h.
//
//The ECC_256 variant of the sign-on protocol uses elliptic curve cryptography for its backend (as opposed to
//RSA). As such, in the diffie hellman exchange of the protocol, ECDH rather than standard diffie hellman is used.
//
//The curves used for both generating the tokens for diffie hellman (called N1pub and N1pri for the client) and
//the KD pub that the client generates both use the secp256_r1 curve as defined by NIST.
//
//The other main way that the sign-on protocol variants can change is in the size of the sign on code, which
//again you can look at sign-on-basic-client.h for more information on.

#define SIGN_ON_BASIC_ECC_256_SECURE_SIGN_ON_CODE_LENGTH 16 ///< The length of the secure sign-on code for the ecc_256 variant.

#define SIGN_ON_BASIC_ECC_256_KD_PRI_RAW_LENGTH 32 ///< The length of the KD key pair private key for the ecc_256 variant.

#endif // SIGN_ON_BASIC_ECC_256_CONSTS_H
