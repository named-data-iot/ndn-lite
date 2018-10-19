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

  // common fields
  TLV_Name = 7,
  TLV_GenericNameComponent = 8,
  TLV_ImplicitSha256DigestComponent = 1,
  TLV_ParametersSha256DigestComponent = 2,

  // Interest packet
  TLV_CanBePrefix = 33,
  TLV_MustBeFresh = 18,
  TLV_ForwardingHint = 30,
  TLV_Nounce = 10,
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
  TLV_NotAfter = 255
};

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_TLV_H
