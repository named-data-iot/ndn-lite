/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NRF_SDK_BLE_ADV_H
#define NRF_SDK_BLE_ADV_H

#include "ble.h"
#include <stdint.h>
#include <stdbool.h>

// ALL FUNCTIONS BELOW THAT RETURN INTEGERS RETURN NRF_BLE_OP_SUCCESS UPON SUCCESS,
// AND NRF_BLE_OP_FAILURE UPON FAILURE.

/**@brief Initialize and start the NRF SDK BLE advertiser.
 *
 * @param[in]   payload          The data to include in the "manufacturer specific data" section of the advertisement packet.
 * @param[in]   payload_len      Length of payload.
 * @param[in]   adv_uuid_full    The service uuid that will be included in advertisements. If NULL is passed in, there will be no
 *                                 service uuid included in the advertisement.
 * @param[in]   extended         If true, this will use extended advertising. If false, will use legacy advertising.
 * @param[in]   num_adverts      This is the number of advertisement packets that will be sent. After this number of advertisements
 *                                 is sent, advertising will stop.
 * @param[in]   on_adv_stop      A callback function that will be called when advertising stops. This function will be called
 *                                 both if num_adverts advertisements are sent, or if advertising is cut off by a call to
 *                                 nrf_sdk_ble_adv_stop.
 */
int nrf_sdk_ble_adv_start(const uint8_t *payload, uint32_t payload_len, ble_uuid_t adv_uuid_full, bool extended, int num_adverts,
                      void (*on_adv_stop) (void));

/**@brief Stop the NRF SDK BLE advertiser. Even if the last call to nrf_sdk_ble_adv_start has not finished (i.e, num_adverts
 *          advertisements have not been sent), this will prematurely stop advertising. This is called at the beginning of every
 *          call to nrf_sdk_ble_adv_start, so that if there are calls to nrf_sdk_ble_adv_start before previous calls have finished,
 *          the most recent call to nrf_sdk_ble_adv_start will cut off the advertisements of previous calls.
 */
int nrf_sdk_ble_adv_stop();

#endif // NRF_SDK_BLE_ADV_H
