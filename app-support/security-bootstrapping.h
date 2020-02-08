/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_APP_SUPPORT_SECURITY_BOOTSTRAPPING_H
#define NDN_APP_SUPPORT_SECURITY_BOOTSTRAPPING_H

#include "../security/ndn-lite-ecc.h"
#include "../security/ndn-lite-hmac.h"
#include "../forwarder/forwarder.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SEC_BOOT_PRE_ECC_PRV_KEY_SIZE 32
#define SEC_BOOT_PRE_ECC_PUB_KEY_SIZE 64
#define SEC_BOOT_PRE_HMAC_KEY_SIZE 16

static const uint32_t SEC_BOOT_PRE_ECC_KEY_ID = 10000;
static const uint32_t SEC_BOOT_PRE_HMAC_KEY_ID = 10001;
static const uint32_t SEC_BOOT_DH_KEY_ID = 10002;
static const uint32_t SEC_BOOT_AES_KEY_ID = 10003;

typedef struct ndn_bootstrapping_info {
  uint8_t* pre_installed_prv_key_bytes;
  uint8_t* pre_installed_pub_key_bytes;
  uint8_t* pre_shared_hmac_key_bytes;
} ndn_bootstrapping_info_t;

typedef struct ndn_device_info {
  char* device_identifier;
  const uint8_t* service_list;
  size_t service_list_size;
} ndn_device_info_t;

typedef void (*ndn_security_bootstrapping_after_bootstrapping) (void);

/**
 * Bootstrapping protocol spec:
 *
 *  Sign on Interest
 *  ==============
 *    Interest Name: /ndn/sign-on
 *    Params: MustBeFresh
 *    AppParams:
 *      NameComponent-TLV: A single name component contains device-identifier
 *      T=TLV_SEC_BOOT_CAPABILITIES L=? V=bytes: Each byte represents a service
 *      T=TLV_SEC_BOOT_N1_ECDH_PUB L=? V=bytes: Bytes of ECDH public key N1
 *    Sig Info:
 *      Key locator: /device-identifier
 *    Sig Value: ECDSA Signature by private key paired with pre-shared public key
 *  ==============
 *  Replied Data
 *  ==============
 *    Content:
 *      Data-TLV: trust anchor cert
 *      T=TLV_SEC_BOOT_N2_ECDH_PUB L=? V=bytes: Bytes of ECDH public key N2
 *      T=TLV_AC_SALT L=? V=bytes: Bytes of salt used in key derivation
 *    Sig Value: Signature by controller identity key
 *  ==============
 *  Adv Interest will be sent periodically based on SD_ADV_INTERVAL ms
 *
 *  Cert Request Interest
 *  ==============
 *    Interest Name: /[home-prefix]/cert
 *    Param: MustBeFresh
 *    AppParams:
 *      NameComponent-TLV: A single name component contains device-identifier
 *      T=TLV_SEC_BOOT_N2_ECDH_PUB L=? V=bytes: Bytes of ECDH public key N2
 *      T=TLV_SEC_BOOT_ANCHOR_DIGEST L=? V=bytes: SHA256 of received trust anchor
 *      T=TLV_SEC_BOOT_N1_ECDH_PUB L=? V=bytes: Bytes of ECDH public key N1
 *    Sig Info:
 *      Key locator: /device-identifier
 *    Sig Value: ECDSA Signature by identity key
 *  ==============
 *  Replied Data
 *  ==============
 *    Content:
 *      Repeated {Name-TLV, uint32_t}: Service name and freshness period in ms
 *    Sig Value: Signature by controller identity key
 *  ==============
 *  Service Query Interest will be sent right after bootstrapping
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
                           const ndn_bootstrapping_info_t* bootstrapping_info,
                           const ndn_device_info_t* device_info,
                           ndn_security_bootstrapping_after_bootstrapping after_bootstrapping);

#ifdef __cplusplus
}
#endif

#endif // NDN_APP_SUPPORT_SECURITY_BOOTSTRAPPING_H
