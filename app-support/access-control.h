/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_APP_SUPPORT_ACCESS_CONTROL_H
#define NDN_APP_SUPPORT_ACCESS_CONTROL_H

#include "../encode/interest.h"
#include "../encode/data.h"

/**
 * Access control protocol spec:
 *
 *  Get EKEY from the controller:
 *  ==============
 *    Interest Name: /[home-prefix]/NDN_SD_AC/NDN_SD_AC_EK/[service-id]
 *    Params: MustBeFresh
 *    Sig Info:
 *      Key locator: /[home-prefix]/[room]/[device-id]
 *    Sig Value:
 *      ECDSA Signature by identity key
 *  ==============
 *  This Interest will be sent right after security bootstrapping.
 *  Repied Data:
 *  ==============
 *    Content:
 *      T=TLV_AC_AES_IV L=? V=bytes: AES IV
 *      T=TLV_AC_ENCRYPTED_PAYLOAD L=? V=bytes: AES encrypted payload, which is the EKEY for the service
 *  ==============
 *
 *  Get DKEY from the controller:
 *  ==============
 *    Interest Name: /[home-prefix]/NDN_SD_AC/NDN_SD_AC_DK/[service-id]
 *    Params: MustBeFresh
 *    Sig Info:
 *      Key locator: /[home-prefix]/[room]/[device-id]
 *    Sig Value:
 *      ECDSA Signature by identity key
 *  ==============
 *  This Interest will be sent right after security bootstrapping.
 *  Repied Data
 *  ==============
 *    Content:
 *      T=TLV_AC_AES_IV L=? V=bytes: AES IV
 *      T=TLV_AC_ENCRYPTED_PAYLOAD L=? V=bytes: AES encrypted payload
 *  ==============
 */

// Basic Design:
// 1. The access control policy are decided by schema
// 2. The access control key can be roll overed by existing key (e.g., through one-way function)
// 3. The access control granularity can be kept in the service type level at the moment

/**
 *  Get a AES key used for data encryption/decryption for service.
 *  @param service. The key for which service will be returned.
 *  @return NULL if there is no such AES key for the service
 */
ndn_aes_key_t*
ndn_ac_get_key_for_service(uint8_t service);

void
ndn_ac_register_encryption_key_request(uint8_t service);

void
ndn_ac_register_access_request(uint8_t service);

void
ndn_ac_after_bootstrapping();

#endif // NDN_APP_SUPPORT_ACCESS_CONTROL_H