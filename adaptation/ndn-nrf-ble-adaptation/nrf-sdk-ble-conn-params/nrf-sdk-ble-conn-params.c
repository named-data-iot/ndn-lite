/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "nrf-sdk-ble-conn-params.h"

#include "nrf-sdk-ble-conn-params-defs.h"

#include "ble_conn_params.h"
#include <string.h>

#include "../nrf-sdk-ble-consts.h"
#include "../nrf-sdk-ble-error-check.h"

#include "../logger.h"

static bool m_init_success = false; /**< Will be true if this module was already initialized successfully. */

void conn_params_error_handler(uint32_t nrf_error)
{
  APP_ERROR_CHECK_IGNORE_INVALID_STATE(nrf_error, "nrf-sdk-ble-conn-params.c, conn_params_error_handler");
}

void on_conn_params_evt(ble_conn_params_evt_t * p_evt)
{
    ret_code_t err_code;

    if (p_evt->evt_type == BLE_CONN_PARAMS_EVT_FAILED)
    {
        APP_LOG("Got BLE_CONN_PARAMS_EVT_FAILED in on_conn_params_evt.\n");
        err_code = sd_ble_gap_disconnect(p_evt->conn_handle, BLE_HCI_CONN_INTERVAL_UNACCEPTABLE);
        APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "on_conn_params_evt, sd_ble_gap_disconnect");
    }
}

int nrf_sdk_ble_conn_params_init(void)
{

    if (m_init_success)
      return;

    ret_code_t             err_code;
    ble_conn_params_init_t cp_init;

    memset(&cp_init, 0, sizeof(cp_init));

    cp_init.p_conn_params                  = NULL;
    cp_init.first_conn_params_update_delay = FIRST_CONN_PARAMS_UPDATE_DELAY;
    cp_init.next_conn_params_update_delay  = NEXT_CONN_PARAMS_UPDATE_DELAY;
    cp_init.max_conn_params_update_count   = MAX_CONN_PARAMS_UPDATE_COUNT;
    cp_init.start_on_notify_cccd_handle    = BLE_GATT_HANDLE_INVALID;
    cp_init.disconnect_on_fail             = false;
    cp_init.evt_handler                    = on_conn_params_evt;
    cp_init.error_handler                  = conn_params_error_handler;

    err_code = ble_conn_params_init(&cp_init);
    APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "nrf_sdk_ble_conn_params_init");
    if (err_code != NRF_SUCCESS) {
      return NRF_BLE_OP_FAILURE;
    }

    m_init_success = true;

    return NRF_BLE_OP_SUCCESS;
}