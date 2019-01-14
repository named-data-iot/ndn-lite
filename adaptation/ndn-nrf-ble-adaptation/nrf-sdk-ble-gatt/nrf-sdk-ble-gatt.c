
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "nrf-sdk-ble-gatt.h"

#include "nrf_ble_gatt.h"

#include "../nrf-sdk-ble-consts.h"
#include "../nrf-sdk-ble-error-check.h"

#include "../nrf-logger.h"

NRF_BLE_GATT_DEF(m_gatt);  /**< GATT module instance. */
static bool m_init_success = false; /**< Will be true if this module was already initialized successfully. */

int nrf_sdk_ble_gatt_init(void)
{

    if (m_init_success)
      return NRF_BLE_OP_SUCCESS;

    ret_code_t err_code = nrf_ble_gatt_init(&m_gatt, NULL);
    APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "nrf_sdk_ble_gatt_init");

    if (err_code != NRF_SUCCESS) {
      return NRF_BLE_OP_FAILURE;
    }

    m_init_success = true;

    return NRF_BLE_OP_SUCCESS;
}