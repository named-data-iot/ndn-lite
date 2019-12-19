/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
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
 *  Repied Data:
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
 *  Repied Data:
 *    Content:
 *      T=TLV_AC_AES_IV L=? V=bytes: AES IV
 *      T=TLV_AC_ENCRYPTED_PAYLOAD L=? V=bytes: AES encrypted payload
 *  ==============
 */

// Basic Design:
// 1. The access control policy are decided by schema
// 2. The access control key can be roll overed by existing key (e.g., through one-way function)
// 3. The access control granularity can be kept in the service type level at the moment

void
ndn_ac_register_service_require_ek(uint8_t service);

void
ndn_ac_register_access_request(uint8_t service);

void
ndn_ac_after_bootstrapping();

#endif // NDN_APP_SUPPORT_ACCESS_CONTROL_H