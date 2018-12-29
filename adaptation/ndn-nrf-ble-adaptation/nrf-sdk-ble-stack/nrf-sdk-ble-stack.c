/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "app_error.h"

#include "nrf-sdk-ble-stack.h"
#include "nrf-sdk-ble-stack-defs.h"

#include "../nrf-sdk-ble-consts.h"

#include "../logger.h"

#define TEMP_BUF_LENGTH 500

static bool m_is_connected; /**< A boolean variable to store whether the device is currently connected to a central. */
nrf_sdk_ble_stack_observer_t m_nrf_sdk_ble_stack_observers[NRF_SDK_BLE_STACK_MAX_OBSERVERS]; /**< An array of all observers. */
static int m_num_nrf_sdk_ble_stack_observers = 0; /**< Current number of observers. */
static bool m_init_success = false; /**< Will be true if this module was already initialized successfully. */

static void ble_evt_handler(ble_evt_t const * p_evt, void * p_context)
{
    ret_code_t err_code = NRF_SUCCESS;

    switch (p_evt->header.evt_id)
    {
        case BLE_GAP_EVT_DISCONNECTED:
            APP_LOG("Disconnected.\n");

            m_is_connected = false;

            for (int i = 0; i < m_num_nrf_sdk_ble_stack_observers; i++) {
              m_nrf_sdk_ble_stack_observers[i].on_disconnected();
            }

            break;

        case BLE_GAP_EVT_CONNECTED:
            APP_LOG("Connected.\n");

            m_is_connected = true;

            for (int i = 0; i < m_num_nrf_sdk_ble_stack_observers; i++) {
              m_nrf_sdk_ble_stack_observers[i].on_connected(p_evt->evt.gap_evt.conn_handle);
            }

            break;

        case BLE_GAP_EVT_PHY_UPDATE_REQUEST:
        {
            APP_LOG("PHY update request.\n");
            ble_gap_phys_t const phys =
            {
                .rx_phys = BLE_GAP_PHY_AUTO,
                .tx_phys = BLE_GAP_PHY_AUTO,
            };
            err_code = sd_ble_gap_phy_update(p_evt->evt.gap_evt.conn_handle, &phys);
            APP_ERROR_CHECK(err_code);
        } break;

        case BLE_GATTC_EVT_TIMEOUT:
            // Disconnect on GATT Client timeout event.
            APP_LOG("GATT Client Timeout.\n");
            err_code = sd_ble_gap_disconnect(p_evt->evt.gattc_evt.conn_handle,
                                             BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
            break;

        case BLE_GATTS_EVT_TIMEOUT:
            // Disconnect on GATT Server timeout event.
            APP_LOG("GATT Server Timeout.\n");
            err_code = sd_ble_gap_disconnect(p_evt->evt.gatts_evt.conn_handle,
                                             BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
            break;

        case BLE_GATTS_EVT_EXCHANGE_MTU_REQUEST:
            APP_LOG("Got a GATTS_EVT_EXCHANGE_MTU_REQUEST\n");

            for (int i = 0; i < m_num_nrf_sdk_ble_stack_observers; i++) {
              m_nrf_sdk_ble_stack_observers[i].on_mtu_rqst(p_evt->evt.gap_evt.conn_handle);
            }

            break;
        
        case BLE_GATTS_EVT_HVN_TX_COMPLETE:
            APP_LOG("Got a BLE_GATTS_EVT_HVN_TX_COMPLETE\n");

            for (int i = 0; i < m_num_nrf_sdk_ble_stack_observers; i++) {
              m_nrf_sdk_ble_stack_observers[i].on_hvn_tx_complete(p_evt->evt.gap_evt.conn_handle);
            }

            break;

        case BLE_GATTC_EVT_EXCHANGE_MTU_RSP:
            APP_LOG("Got a BLE_GATTC_EVT_EXCHANGE_MTU_RSP\n");

            break;

        default:
            // No implementation needed.
            break;
    }
}

static int
ble_stack_init(void)
{
  ret_code_t err_code;

  err_code = nrf_sdh_enable_request();
  if (err_code != NRF_SUCCESS) {
    APP_LOG("in ble_stack_init, nrf_sdh_enable_request failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  // Configure the BLE stack using the default settings.
  // Fetch the start address of the application RAM.
  uint32_t ram_start = 0;
  err_code = nrf_sdh_ble_default_cfg_set(APP_BLE_CONN_CFG_TAG, &ram_start);
  if (err_code != NRF_SUCCESS) {
    APP_LOG("in ble_stack_init, nf_sdh_ble_default_cfg_set failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  // Overwrite some of the default configurations for the BLE stack.
  ble_cfg_t ble_cfg;

  // Enable BLE stack.
  err_code = nrf_sdh_ble_enable(&ram_start);
  if (err_code != NRF_SUCCESS) {
    APP_LOG("in ble_stack_init, nrf_sdh_ble_enable failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  // Register a handler for BLE events.
  NRF_SDH_BLE_OBSERVER(m_ble_observer, APP_BLE_OBSERVER_PRIO, ble_evt_handler, NULL);

  return NRF_BLE_OP_SUCCESS;
}

int nrf_sdk_ble_stack_init()
{

  if (m_init_success)
    return NRF_BLE_OP_SUCCESS;

  if (ble_stack_init() != NRF_BLE_OP_SUCCESS) {
    APP_LOG("in ble_init(), ble_stack_init() failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  m_init_success = true;
  
  return NRF_BLE_OP_SUCCESS;

}

int nrf_sdk_ble_stack_add_observer(nrf_sdk_ble_stack_observer_t observer) {
  m_nrf_sdk_ble_stack_observers[m_num_nrf_sdk_ble_stack_observers++] = observer;
  APP_LOG("Current number of observers of nrf sdk ble stack: %d\n", m_num_nrf_sdk_ble_stack_observers);

  return NRF_BLE_OP_SUCCESS;
}

bool nrf_sdk_ble_stack_connected() {
  return m_is_connected;
}