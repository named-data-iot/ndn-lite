/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_APP_SUPPORT_SERVICE_DISCOVERY_H
#define NDN_APP_SUPPORT_SERVICE_DISCOVERY_H

#include "../encode/interest.h"
#include "../encode/data.h"
#include "../util/uniform-time.h"
#include "../forwarder/face.h"

#ifdef __cplusplus
extern "C" {
#endif

const static uint32_t SD_ADV_INTERVAL = 15000;

/**
 * Service discovery protocol spec:
 *
 *  Advertisement:
 *  ==============
 *    Interest Name: /[home-prefix]/NDN_SD_SD/NDN_SD_SD_AD/[room]/[device-id]
 *    Params: MustBeFresh
 *    AppParams:
 *      4 bytes: Freshness period (uint32_t)
 *      bytes: Each byte represents a service
 *    Sig Info:
 *      Key locator: /[home-prefix]/[room]/[device-id]
 *    Sig Value:
 *      ECDSA Signature by identity key
 *  ==============
 *  Adv Interest will be sent periodically based on SD_ADV_INTERVAL ms
 *
 *  Service Query to the Controller
 *  ==============
 *    Interest Name: /[home-prefix]/NDN_SD_SD_CTL/NDN_SD_SD_CTL_META
 *    Param: MustBeFresh
 *    AppParams:
 *      bytes: each byte represents an interested service
 *    Sig Info:
 *      Key locator: /[home-prefix]/[room]/[device-id]
 *    Sig Value:
 *      ECDSA signature by identity key
 *  ==============
 *  Replied Data
 *  ==============
 *    Content:
 *      Repeated {Name-TLV, uint32_t}: service name and freshness period
 *    Sig Value: ECDSA Signature by controller identity key
 *  ==============
 *  Service Query Interest will be sent right after bootstrapping
 *
 */

/**
 * Load a device's meta info into the state.
 * @param face. Input. The network interface to listen to.
 * This function will be called by Bootstrapping module automatically.
 * Service Discovery relies on two components obtained from Bootstrapping process:
 *  1. self_identity, which is kept in ndn_key_storage.self_identity
 *  2. self_identity_key, which is kept in ndn_key_storage.self_identity_key
 */
void
ndn_sd_after_bootstrapping(ndn_face_intf_t *face);

/**
 * Add a service provided by self device into the state.
 * Use before or after ndn_sd_after_bootstrapping.
 * @param service_id. Input. Service ID.
 * @param adv. Input. Whether to advertise.
 * @param status_code. Input. The status of the service.
 * @return NDN_SUCCESS if there is no error.
 */
int
sd_add_or_update_self_service(uint8_t service_id, bool adv, uint8_t status_code);

/**
 * Add an interested service type so sd will cache related service provider information.
 * Use before or after ndn_sd_after_bootstrapping.
 * @param service_id. Input. Service ID.
 * @return NDN_SUCCESS if there is no error.
 */
int
sd_add_interested_service(uint8_t service_id);

/**
 * Express an Interest packet to query the SPs for the service.
 * ONLY after ndn_sd_after_bootstrapping.
 * @param service_id. Input. The service to be queried.
 * @param is_any. Input. If is true, query one SP that can provide the service.
 *   If is false, query all the SPs that can provide the service.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
sd_query_service(uint8_t service_id, const ndn_name_t* granularity, bool is_any);

#ifdef __cplusplus
}
#endif

#endif // NDN_APP_SUPPORT_SERVICE_DISCOVERY_H
