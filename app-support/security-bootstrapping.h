/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#ifndef NDN_APP_SUPPORT_SECURITY_BOOTSTRAPPING_H
#define NDN_APP_SUPPORT_SECURITY_BOOTSTRAPPING_H

#include "../security/ndn-lite-ecc.h"
#include "../security/ndn-lite-hmac.h"
#include "../forwarder/forwarder.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ndn_security_bootstrapping_after_bootstrapping) (void);

/**
 * Bootstrapping protocol spec:
 *
 *  Sign on Interest
 *  ==============
 *    Interest Name: /ndn/sign-on
 *    Params: MustBeFresh
 *    AppParams:
 *      NameComponent-TLV
 *      T=TLV_SEC_BOOT_CAPABILITIES L=? V=byte array, each byte represents a service
 *      T=TLV_SEC_BOOT_N1_ECDH_PUB L=? V=byte array of ECDH public key
 *    ECDSA Signature by private key paired with pre-shared public key
 *  ==============
 *  Adv Interest will be sent periodically based on SD_ADV_INTERVAL ms
 *
 *  Service Query from Controller
 *  ==============
 *    Interest Name: /[home-prefix]/NDN_SD_SD_CTL/NDN_SD_SD_CTL_META
 *    Param: MustBeFresh
 *    AppParams: 0- bytes: byte array, each byte represents an interested service
 *    Signature by identity key
 *  ==============
 *    Replied Data Content: a list of {Name-TLV, uint32_t}
 *    Signature by controller identity key
 *  ==============
 *  Service Query Interest will be sent right after bootstrapping
 *
 */

/**
 * Start the security boostrapping process.
 * @param device_identifier. INPUT. A string uniquely represent the device, e.g., a randomness.
 * @param len. INPUT. The len of the string.
 * @param service_list. INPUT. A array of uint8_t, each uint8_t represents a service provided by the device.
 * @param list_size. INPUT. The list size.
 */
int
ndn_security_bootstrapping(ndn_face_intf_t* face,
                           const ndn_ecc_prv_t* pre_installed_prv_key, const ndn_hmac_key_t* pre_shared_hmac_key,
                           const char* device_identifier, size_t len,
                           const uint8_t* service_list, size_t list_size,
                           ndn_security_bootstrapping_after_bootstrapping after_bootstrapping);

#ifdef __cplusplus
}
#endif

#endif // NDN_APP_SUPPORT_SECURITY_BOOTSTRAPPING_H
