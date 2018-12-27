/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "nrf-sdk-ble-scan.h"

#include "nrf_ble_scan.h"
#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "nrf_sdh_soc.h"

#include "../nrf-sdk-ble-consts.h"

#include "../logger.h"

NRF_BLE_SCAN_DEF(m_scan); /**< Scanning module instance. */
void (*m_on_scan)(const uint8_t *scan_data, uint8_t scan_data_len) = NULL; /**< Callback function for scan events. */
ble_gap_scan_params_t m_scan_param = /**< Scan parameters requested for scanning and connection. */
    {
        .active = 0x00,
        .interval = NRF_BLE_SCAN_SCAN_INTERVAL,
        .window = NRF_BLE_SCAN_SCAN_WINDOW,
        .filter_policy = BLE_GAP_SCAN_FP_ACCEPT_ALL,
        .timeout = NRF_BLE_SCAN_SCAN_DURATION,
        .scan_phys = BLE_GAP_PHY_1MBPS,
        .extended = 1,
};

int scan_start(void) {
  ret_code_t err_code;

  err_code = nrf_ble_scan_start(&m_scan);
  if (err_code != NRF_SUCCESS) {
    APP_LOG("in scan_start, nrf_ble_scan_start failed\n");
    return NRF_BLE_OP_FAILURE;
  }

  return NRF_BLE_OP_SUCCESS;
}

void scan_evt_handler(scan_evt_t const *p_scan_evt) {
  switch (p_scan_evt->scan_evt_id) {
  case NRF_BLE_SCAN_EVT_SCAN_TIMEOUT: {
    APP_LOG("Scan timed out.\n");
    scan_start();
  } break;
  case NRF_BLE_SCAN_EVT_FILTER_MATCH: {
    APP_LOG("Got a filter match!\n");
    const ble_gap_evt_adv_report_t *p_adv_report = p_scan_evt->params.filter_match.p_adv_report;
    if (m_on_scan != NULL) {
      m_on_scan(p_adv_report->data.p_data, p_adv_report->data.len);
    }
  }
  default:
    break;
  }
}

int scan_init(ble_uuid_t scan_uuid) {

  ret_code_t err_code;
  nrf_ble_scan_init_t init_scan;

  memset(&init_scan, 0, sizeof(init_scan));

  init_scan.connect_if_match = false;
  init_scan.conn_cfg_tag = APP_BLE_CONN_CFG_TAG;
  init_scan.p_scan_param = &m_scan_param;

  err_code = nrf_ble_scan_init(&m_scan, &init_scan, scan_evt_handler);
  if (err_code != NRF_SUCCESS) {
    APP_LOG("in scan_init, nrf_ble_scan_init failed\n");
    return NRF_BLE_OP_FAILURE;
  }

  err_code = nrf_ble_scan_filter_set(&m_scan, SCAN_UUID_FILTER, &scan_uuid);
  if (err_code != NRF_SUCCESS) {
    APP_LOG("in scan_init, nrf_ble_scan_filter_set failed\n");
    return NRF_BLE_OP_FAILURE;
  }

  err_code = nrf_ble_scan_filters_enable(&m_scan,NRF_BLE_SCAN_ALL_FILTER, false);
  if (err_code != NRF_SUCCESS) {
    APP_LOG("in scan_init, nrf_ble_scan_filters_enable failed\n");
    return NRF_BLE_OP_FAILURE;
  }

  return NRF_BLE_OP_SUCCESS;
}

int nrf_sdk_ble_scan_start(void (*on_scan)(const uint8_t *scan_data, uint8_t scan_data_len)) {
  m_on_scan = on_scan;

  if (scan_start() != NRF_BLE_OP_SUCCESS) {
    APP_LOG("in nrf_sdk_ble_scan_start, scan_start failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  return NRF_BLE_OP_SUCCESS;
}

int nrf_sdk_ble_scan_init(ble_uuid_t scan_uuid) {
  if (scan_init(scan_uuid) != NRF_BLE_OP_SUCCESS) {
    APP_LOG("in ble_init(), scan_init() failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  return NRF_BLE_OP_SUCCESS;
}