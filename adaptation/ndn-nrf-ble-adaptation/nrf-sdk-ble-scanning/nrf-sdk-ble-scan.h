/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NRF_SDK_BLE_SCAN_H
#define NRF_SDK_BLE_SCAN_H

#include "ble.h"

// ALL FUNCTIONS BELOW THAT RETURN INTEGERS RETURN NRF_BLE_OP_SUCCESS UPON SUCCESS,
// AND NRF_BLE_OP_FAILURE UPON FAILURE.

/**@brief Initialize the NRF SDK BLE scanner.
 *
 * @param[in]   scan_uuid     This UUID will be used as a filter during scanning; only advertisements
 *                              including this UUID will be detected.
 */
int nrf_sdk_ble_scan_init(ble_uuid_t scan_uuid);

/**@brief Start the NRF SDK BLE scanner.
 *
 * @param[in]   on_scan        Callback function for scan event.
 */
int nrf_sdk_ble_scan_start(void (*on_scan)(const uint8_t *scan_data, uint8_t scan_data_len));

#endif // NRF_SDK_BLE_SCAN_H