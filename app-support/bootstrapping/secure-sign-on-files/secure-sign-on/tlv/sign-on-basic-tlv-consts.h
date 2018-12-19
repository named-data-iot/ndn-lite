/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_TLV_CONSTS_H
#define SIGN_ON_BASIC_TLV_CONSTS_H

/** @defgroup TLV types used in the construction and parsing of Sign-on Basic messages.
 * @{ */
static const int SECURE_SIGN_ON_BOOTSTRAPPING_REQUEST_RESPONSE_TLV_TYPE = 0x00;
static const int SECURE_SIGN_ON_CERTIFICATE_REQUEST_RESPONSE_TLV_TYPE = 0x01;
static const int SECURE_SIGN_ON_BOOTSTRAPPING_REQUEST_TLV_TYPE = 0x02;
static const int SECURE_SIGN_ON_CERTIFICATE_REQUEST_TLV_TYPE = 0x03;
static const int SECURE_SIGN_ON_DEVICE_IDENTIFIER_TLV_TYPE = 0x04;
static const int SECURE_SIGN_ON_DEVICE_CAPABILITIES_TLV_TYPE = 0x05;
static const int SECURE_SIGN_ON_N1_PUB_TLV_TYPE = 0x06;
static const int SECURE_SIGN_ON_SIGNATURE_TLV_TYPE = 0x07;
static const int SECURE_SIGN_ON_N2_PUB_TLV_TYPE = 0x08;
static const int SECURE_SIGN_ON_ANCHOR_CERTIFICATE_TLV_TYPE = 0x09;
static const int SECURE_SIGN_ON_TRUST_ANCHOR_CERTIFICATE_DIGEST_TLV_TYPE = 0x10;
static const int SECURE_SIGN_ON_N2_PUB_DIGEST_TLV_TYPE = 0x11;
static const int SECURE_SIGN_ON_KD_PRI_ENCRYPTED_TLV_TYPE = 0x12;
static const int SECURE_SIGN_ON_KD_PUB_CERTIFICATE_TLV_TYPE = 0x13;
static const int SECURE_SIGN_ON_FINISH_MESSAGE_TLV_TYPE = 0x14;
static const int SECURE_SIGN_ON_FINISH_CODE_TLV_TYPE = 0x15;
/** @} */


#endif // SIGN_ON_BASIC_TLV_CONSTS_H