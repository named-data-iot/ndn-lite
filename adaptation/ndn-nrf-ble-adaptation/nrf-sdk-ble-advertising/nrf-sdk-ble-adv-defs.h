/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NRF_SDK_BLE_ADV_DEFS_H
#define NRF_SDK_BLE_ADV_DEFS_H

// the code below was adapted from this example: https://devzone.nordicsemi.com/f/nordic-q-a/37604/extended-advertising-scannable

#define MANUFACTURER_NAME "" /**< Manufacturer. Passed to Device Information Service. */
#define APP_ADV_INTERVAL 300 /**< The advertising interval (in units of 0.625 ms). This value corresponds to 187.5 ms. */
#define APP_ADV_DURATION 90  /**< The advertising duration (180 seconds) in units of 10 milliseconds. */

// https://devzone.nordicsemi.com/f/nordic-q-a/41180/maximum-amount-of-data-that-can-be-sent-through-extended-advertisements-nrf52840
#define NRF_BLE_EXT_ADV_MAX_PAYLOAD 218

#endif // NRF_SDK_BLE_ADV_DEFS_H