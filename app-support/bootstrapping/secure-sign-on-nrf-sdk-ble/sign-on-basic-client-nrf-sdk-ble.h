/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_CLIENT_NRF_SDK_BLE_H
#define SIGN_ON_BASIC_CLIENT_NRF_SDK_BLE_H

#include "../../adaptation/ndn-nrf-ble-adaptation/nrf-sdk-ble-ndn-lite-ble-unicast-transport/nrf-sdk-ble-ndn-lite-ble-unicast-transport.h"

#include "../secure-sign-on/sign-on-basic-client.h"
#include "../secure-sign-on/sign-on-basic-client-consts.h"
#include "../secure-sign-on/sign-on-basic-consts.h"

/**@brief Structure for keeping track of state for a given Sign-on Basic nRF SDK BLE client.
 *          This is an implementation of a client for the sign-on protocol, utilizing Bluetooth Low
 *          Energy as the transport and using the nRF SDK's Bluetooth Low Energy support as the
 *          backend for the transport implementation.
 *          All of the information in the object related to the sign-on protocol is stored within 
 *          a sign_on_basic_client object; the pointers to data here actually point to
 *          the structures within this sign_on_basic_client object.
 *                 
 * @var         trust_anchor_cert_p        See the sign_on_basic_client_t documentation in "sign-on-basic-client.h".
 * @var         trust_anchor_cert_len      "                                               "
 * @var         KD_pub_cert_p              "                                               "
 * @var         KD_pub_cert_len            "                                               "
 * @var         KD_pri_p                   "                                               "
 * @var         KD_pri_len                 "                                               "
 *
 */
typedef struct sign_on_basic_client_nrf_sdk_ble {
  uint8_t *trust_anchor_cert_p;
  uint32_t trust_anchor_cert_len;
  uint8_t *KD_pub_cert_p;
  uint32_t KD_pub_cert_len;
  uint8_t *KD_pri_p;
  uint32_t KD_pri_len;
} sign_on_basic_client_nrf_sdk_ble_t;

/**@brief There should be only one sign_on_basic_client_nrf_sdk_ble. Use this function
 *          to get the singleton instance. If the instance has not been initialized,
 *          call sign_on_basic_client_nrf_sdk_ble_construct first.
 */
sign_on_basic_client_nrf_sdk_ble_t*
get_sign_on_basic_client_nrf_sdk_ble_instance();

/**@brief Function to construct a sign_on_basic_client_nrf_sdk_ble_t. All buffers passed 
 *          in will be copied into the sign_on_basic_client object associated with this
 *          sign_on_basic_client_nrf_sdk_ble_t.
 *
 * @param[in]   variant                    This is the variant of the Sign-On basic protocol that you
 *                                           want to initialize. This will change the function pointers that 
 *                                           are passed to sign_on_basic_sec_intf to do security related
 *                                           operations, like signature generation.
 *                                         See secure-sign-on-basic-consts.h for all of the variants, as  
 *                                           well as descriptions.
 * @param[in]   device_identifier_p        See the sign_on_basic_client_t documentation in "sign-on-basic-client.h".
 * @param[in]   device_identifier_len      "                                               "
 * @param[in]   device_capabilities_p      "                                               "                                       
 * @param[in]   device_capabilities_len    "                                               "
 * @param[in]   secure_sign_on_code_p      "                                               "
 * @param[in]   KS_pub_p                   "                                               "
 * @param[in]   KS_pub_len                 "                                               "
 * @param[in]   KS_pri_p                   "                                               "
 * @param[in]   KS_pri_len                 "                                               "
 *
 * @param[in]   on_sign_on_completed       Callback function to be triggered when the sign on process
 *                                           has been completed. The sign on process is considered finished
 *                                           when the finish message has been successfully generated and sent.
 *                                           See ndn-error-code.h for a list of possible return values here.
 *                                         The result_code parameter will be NDN_SUCCESS upon a successfully
 *                                           completed sign-on, and will be a return code from the Sign-on Protocol
 *                                           or Sign-On Protocol Over BLE section of ndn-error-code.h otherwise.
 *
 */
int sign_on_basic_client_nrf_sdk_ble_construct(
                              uint8_t variant,
                              const uint8_t *device_identifier_p, uint32_t device_identifier_len,
                              const uint8_t *device_capabilities_p, uint32_t device_capabilities_len,
                              const uint8_t *secure_sign_on_code_p,
                              const uint8_t *KS_pub_p, uint32_t KS_pub_len,
                              const uint8_t *KS_pri_p, uint32_t KS_pri_len,
                              void (*on_sign_on_completed)(int result_code));

#endif // SIGN_ON_BASIC_CLIENT_NRF_SDK_BLE_H