/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_TLV_H
#define NDN_ENCODING_TLV_H

#ifdef __cplusplus
extern "C" {
#endif

// NDN Packet Format 0.3
enum {
  // packet types
  TLV_Interest = 5,
  TLV_Data = 6,

  // common elements
  TLV_Name = 7,
  TLV_GenericNameComponent = 8,
  TLV_ImplicitSha256DigestComponent = 1,
  TLV_ParametersSha256DigestComponent = 2,

  // Interest packet
  TLV_CanBePrefix = 33,
  TLV_MustBeFresh = 18,
  TLV_ForwardingHint = 30,
  TLV_Nonce = 10,
  TLV_InterestLifetime = 12,
  TLV_HopLimit = 34,
  TLV_Parameters = 35,

  // Data packet
  TLV_MetaInfo = 20,
  TLV_Content = 21,
  TLV_SignatureInfo = 22,
  TLV_SignatureValue = 23,

  // Data/MetaInfo
  TLV_ContentType = 24,
  TLV_FreshnessPeriod = 25,
  TLV_FinalBlockId = 26,

  // Data/Signature
  TLV_SignatureType = 27,
  TLV_KeyLocator = 28,
  TLV_KeyLocatorDigest = 29,

  // Link Object
  TLV_Delegation = 31,
  TLV_Preference = 30,

  // Certificate
  TLV_ValidityPeriod = 253,
  TLV_NotBefore = 254,
  TLV_NotAfter = 255,

  // Command Interest
  TLV_SignedInterestParameters = 60,
  TLV_SignedInterestTimestamp = 61,
};

// App Support Specific
enum {
  TLV_AC_KEY_TYPE = 128,
  TLV_AC_KEY_ID = 128,
  TLV_AC_ECDH_PUB = 130,
  TLV_AC_SALT = 131,
  TLV_AC_KEY_LIFETIME = 132,
  TLV_AC_CIPHER_DK = 133,

  TLV_AC_ENCRYPTED_CONTENT = 134,
  TLV_AC_AES_IV = 135,
  TLV_AC_ENCRYPTED_PAYLOAD = 136,

  TLV_SD_STATUS = 137,

  TLV_SSP_BOOTSTRAPPING_REQUEST_RESPONSE = 138,
  TLV_SSP_CERTIFICATE_REQUEST_RESPONSE = 139,
  TLV_SSP_BOOTSTRAPPING_REQUEST = 140,
  TLV_SSP_CERTIFICATE_REQUEST = 141,
  TLV_SSP_DEVICE_IDENTIFIER = 142,
  TLV_SSP_DEVICE_CAPABILITIES = 143,
  TLV_SSP_N1_PUB = 144,
  TLV_SSP_SIGNATURE = 145,
  TLV_SSP_N2_PUB = 146,
  TLV_SSP_ANCHOR_CERTIFICATE = 147,
  TLV_SSP_TRUST_ANCHOR_CERTIFICATE_DIGEST = 148,
  TLV_SSP_N2_PUB_DIGEST = 149,
  TLV_SSP_KD_PRI_ENCRYPTED = 150,
  TLV_SSP_KD_PUB_CERTIFICATE = 151,
  TLV_SSP_FINISH_MESSAGE = 152,
};

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_TLV_H
