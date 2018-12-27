/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "nrf-sdk-ble-gap.h"

#include "nrf-sdk-ble-gap-defs.h"

#include "../nrf-sdk-ble-consts.h"
#include "../nrf-sdk-ble-error-check.h"

static bool m_init_success = false; /**< Will be true if this module was already initialized successfully. */

int nrf_sdk_ble_gap_init(void)
{

    if (m_init_success)
      return NRF_BLE_OP_SUCCESS;

    ret_code_t              err_code;
    ble_gap_conn_params_t   gap_conn_params;
    ble_gap_conn_sec_mode_t sec_mode;

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&sec_mode);

    err_code = sd_ble_gap_device_name_set(&sec_mode,
                                          (const uint8_t *)DEVICE_NAME,
                                          strlen(DEVICE_NAME));
    APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "nrf_sdk_ble_gap_init, sd_ble_gap_device_name_set");

    memset(&gap_conn_params, 0, sizeof(gap_conn_params));

    gap_conn_params.min_conn_interval = MIN_CONN_INTERVAL;
    gap_conn_params.max_conn_interval = MAX_CONN_INTERVAL;
    gap_conn_params.slave_latency     = SLAVE_LATENCY;
    gap_conn_params.conn_sup_timeout  = CONN_SUP_TIMEOUT;

    err_code = sd_ble_gap_ppcp_set(&gap_conn_params);
    APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "nrf_sdk_ble_gap_init, sd_ble_gap_ppcp_set");

    m_init_success = true;

    return NRF_BLE_OP_SUCCESS;
    
}