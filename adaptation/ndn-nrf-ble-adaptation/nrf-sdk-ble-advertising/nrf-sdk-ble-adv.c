/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "nrf-sdk-ble-adv.h"

#include "nrf-sdk-ble-adv-defs.h"

#include "app_error.h"
#include "ble_advdata.h"
#include "ble_advertising.h"
#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "nrf_sdh_soc.h"

#include "../logger.h"
#include "../nrf-sdk-ble-consts.h"
#include "../nrf-sdk-ble-error-check.h"

BLE_ADVERTISING_DEF(m_advertising);   /**< Advertising module instance */
int m_adv_burst_num;                  /** How many total advertisements should be sent for the last call to nrf_sdk_ble_adv_start */
volatile int m_current_adv_count = 0; /**< How many advertisements have been sent for the last call to nrf_sdk_ble_adv_start */
ble_uuid_t m_adv_uuid;                /**< UUID to use in advertisements based on last call to nrf_sdk_ble_adv_start */
void (*m_on_adv_stop)(void) = NULL;   /**< Reference to callback function for when advertising stops based on last call to nrf_sdk_ble_adv_start */

int advertising_init(const uint8_t *payload, uint32_t payload_len, ble_uuid_t adv_uuid, bool extended);
bool config_is_valid_custom(ble_adv_modes_config_t const *const p_config);
uint32_t ble_advertising_init_custom(ble_advertising_t *const p_advertising, ble_advertising_init_t const *const p_init);

void assert_nrf_callback(uint16_t line_num, const uint8_t *p_file_name) {
  app_error_handler(0xDEADBEEF, line_num, p_file_name);
}

int nrf_sdk_ble_adv_stop() {

  APP_LOG("nrf_sdk_ble_adv_stop was called.\n");

  ret_code_t ret = sd_ble_gap_adv_stop(m_advertising.adv_handle);
  switch (ret) {
  case NRF_SUCCESS: {
    APP_LOG("sd_ble_gap_adv_stop returned NRF_SUCCESS\n");
    break;
  }
  case NRF_ERROR_INVALID_STATE: {
    APP_LOG("sd_ble_gap_adv_stop returned NRF_ERROR_INVALID_STATE\n");
    break;
  }
  case BLE_ERROR_INVALID_ADV_HANDLE: {
    APP_LOG("sd_ble_gap_adv_stop returned BLE_ERROR_INVALID_ADV_HANDLE\n");
    break;
  }
  default: {
    APP_LOG("sd_ble_gap_adv_stop returned unexpected: %d\n", ret);
    break;
  }
  }

  // it is okay if the return value is NRF_ERROR_INVALID_STATE, that means we weren't advertising
  if (ret != NRF_SUCCESS && ret != NRF_ERROR_INVALID_STATE) {
    APP_LOG("in nrf_sdk_ble_adv_stop, return of sd_ble_gap_adv_stop was not NRF_SUCCESS or NRF_ERROR_INVALID_STATE\n");
    return NRF_BLE_OP_FAILURE;
  }

  if (m_on_adv_stop != NULL) {
    if (ret != NRF_ERROR_INVALID_STATE) {
      m_on_adv_stop();
    }
  }

  return NRF_BLE_OP_SUCCESS;
}

int nrf_sdk_ble_adv_start(const uint8_t *payload, uint32_t payload_len, ble_uuid_t adv_uuid, bool extended, int num_adverts,
    void (*on_adv_stop)(void)) {

  m_current_adv_count = 0;

  APP_LOG("Value of m_current_adv_count in nrf_sdk_ble_adv_start: %d\n", m_current_adv_count);

  m_adv_burst_num = num_adverts;

  ret_code_t err_code;

  // stop any advertising that was already happening
  if (nrf_sdk_ble_adv_stop() != NRF_BLE_OP_SUCCESS) {
    APP_LOG("in nrf_sdk_ble_adv_start, nrf_sdk_ble_adv_stop failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  m_on_adv_stop = on_adv_stop;

  if (advertising_init(payload, payload_len, adv_uuid, extended) != NRF_BLE_OP_SUCCESS) {
    APP_LOG("in nrf_sdk_ble_adv_start, advertising_init failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  err_code = ble_advertising_start(&m_advertising, BLE_ADV_MODE_FAST);
  if (err_code != NRF_SUCCESS) {
    APP_LOG("in nrf_sdk_ble_adv_start, ble_advertising_start failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  if (extended) {
    APP_LOG("Successfully started extended advertising.\n");
  } else {
    APP_LOG("Successfully started legacy advertising.\n");
  }

  return NRF_BLE_OP_SUCCESS;
}

void on_adv_evt(ble_adv_evt_t ble_adv_evt) {
  switch (ble_adv_evt) {
  case BLE_ADV_EVT_FAST: {
    APP_LOG("Started ble advertising.\n");
    m_current_adv_count++;
    APP_LOG("Current adv count: %d\n", m_current_adv_count);
    if (m_current_adv_count > m_adv_burst_num) {
      APP_LOG("in on_adv_evt, m_current_adv_count exceeded m_adv_burst_num (current value %d), stopping advertisement.\n", m_adv_burst_num);
      nrf_sdk_ble_adv_stop();
    }
  } break;

  case BLE_ADV_EVT_IDLE: {
    APP_LOG("BLE_ADV_EVT_IDLE was detected in on_adv_evt\n");
    ret_code_t err_code = ble_advertising_start(&m_advertising, BLE_ADV_MODE_FAST);
    if (err_code != NRF_SUCCESS)
      APP_LOG("in on_adv_evt, ble_advertising_start failed.\n");
  } break;

  default:
    // No implementation needed.
    break;
  }
}

int advertising_init(const uint8_t *payload, uint32_t payload_len, ble_uuid_t adv_uuid, bool extended) {
  if (payload_len > NRF_BLE_EXT_ADV_MAX_PAYLOAD) {
    APP_LOG("advertising_init failed; payload_len was larger than NRF_BLE_EXT_ADV_MAX_PAYLOAD\n");
    return NRF_BLE_OP_FAILURE;
  }

  ret_code_t err_code;
  ble_advertising_init_t init;

  memset(&init, 0, sizeof(init));

  m_adv_uuid = adv_uuid;

  init.advdata.include_ble_device_addr = true;
  init.advdata.name_type = BLE_ADVDATA_NO_NAME;
  init.advdata.include_appearance = false;
  init.advdata.flags = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;
  init.advdata.uuids_complete.uuid_cnt = 1;
  init.advdata.uuids_complete.p_uuids = &m_adv_uuid;

  if (payload != NULL) {
    ble_advdata_manuf_data_t manuf_data;    // Variable to hold manufacturer specific data
    manuf_data.company_identifier = 0xFFFF; // Filler company ID
    manuf_data.data.p_data = payload;
    manuf_data.data.size = payload_len;
    init.advdata.p_manuf_specific_data = &manuf_data;

    APP_LOG("Size of manufacturer specific data: %d", manuf_data.data.size);
  }

  init.config.ble_adv_extended_enabled = extended;
  init.config.ble_adv_fast_enabled = true;
  init.config.ble_adv_fast_interval = APP_ADV_INTERVAL;
  init.config.ble_adv_fast_timeout = APP_ADV_DURATION;

  init.evt_handler = on_adv_evt;

  err_code = ble_advertising_init_custom(&m_advertising, &init);
  if (err_code != NRF_SUCCESS) {
    APP_LOG("in advertising_init, ble_advertising_init_custom_failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  ble_advertising_conn_cfg_tag_set(&m_advertising, APP_BLE_CONN_CFG_TAG);

  return NRF_BLE_OP_SUCCESS;
}

bool config_is_valid_custom(ble_adv_modes_config_t const *const p_config) {
  if ((p_config->ble_adv_directed_high_duty_enabled == true) &&
      (p_config->ble_adv_extended_enabled == true)) {
    return false;
  }
#if !defined(S140)
  else if (p_config->ble_adv_primary_phy == BLE_GAP_PHY_CODED ||
           p_config->ble_adv_secondary_phy == BLE_GAP_PHY_CODED) {
    return false;
  }
#endif // !defined (S140)
  else {
    return true;
  }
}

uint32_t ble_advertising_init_custom(ble_advertising_t *const p_advertising,
    ble_advertising_init_t const *const p_init) {
  uint32_t ret;
  if ((p_init == NULL) || (p_advertising == NULL)) {
    return NRF_ERROR_NULL;
  }
  if (!config_is_valid_custom(&p_init->config)) {
    return NRF_ERROR_INVALID_PARAM;
  }

  p_advertising->adv_mode_current = BLE_ADV_MODE_IDLE;
  p_advertising->adv_modes_config = p_init->config;
  p_advertising->conn_cfg_tag = BLE_CONN_CFG_TAG_DEFAULT;
  p_advertising->evt_handler = p_init->evt_handler;
  p_advertising->error_handler = p_init->error_handler;
  p_advertising->current_slave_link_conn_handle = BLE_CONN_HANDLE_INVALID;
  p_advertising->p_adv_data = &p_advertising->adv_data;

  memset(&p_advertising->peer_address, 0, sizeof(p_advertising->peer_address));

  // Copy advertising data.
  if (!p_advertising->initialized) {
    p_advertising->adv_handle = BLE_GAP_ADV_SET_HANDLE_NOT_SET;
  }
  p_advertising->adv_data.adv_data.p_data = p_advertising->enc_advdata;

  if (p_advertising->adv_modes_config.ble_adv_extended_enabled == true) {
#ifdef BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED
    p_advertising->adv_data.adv_data.len = BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED;
#else
    p_advertising->adv_data.adv_data.len = BLE_GAP_ADV_SET_DATA_SIZE_MAX;
#endif // BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED
  } else {
    p_advertising->adv_data.adv_data.len = BLE_GAP_ADV_SET_DATA_SIZE_MAX;
  }

  ret = ble_advdata_encode(&p_init->advdata, p_advertising->enc_advdata, &p_advertising->adv_data.adv_data.len);
  VERIFY_SUCCESS(ret);

  if (&p_init->srdata != NULL) {
    p_advertising->adv_data.scan_rsp_data.p_data = p_advertising->enc_scan_rsp_data;
    if (p_advertising->adv_modes_config.ble_adv_extended_enabled == true) {
#ifdef BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED
      p_advertising->adv_data.scan_rsp_data.len = BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED;
#else
      p_advertising->adv_data.scan_rsp_data.len = BLE_GAP_ADV_SET_DATA_SIZE_MAX;
#endif // BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED
    } else {
      p_advertising->adv_data.scan_rsp_data.len = BLE_GAP_ADV_SET_DATA_SIZE_MAX;
    }
    ret = ble_advdata_encode(&p_init->srdata,
        p_advertising->adv_data.scan_rsp_data.p_data,
        &p_advertising->adv_data.scan_rsp_data.len);
    VERIFY_SUCCESS(ret);
  } else {
    p_advertising->adv_data.scan_rsp_data.p_data = NULL;
    p_advertising->adv_data.scan_rsp_data.len = 0;
  }

  // Configure a initial advertising configuration. The advertising data and and advertising
  // parameters will be changed later when we call @ref ble_advertising_start, but must be set
  // to legal values here to define an advertising handle.
  p_advertising->adv_params.primary_phy = BLE_GAP_PHY_1MBPS;
  p_advertising->adv_params.duration = p_advertising->adv_modes_config.ble_adv_fast_timeout;
  p_advertising->adv_params.properties.type = BLE_GAP_ADV_TYPE_NONCONNECTABLE_SCANNABLE_UNDIRECTED;
  p_advertising->adv_params.p_peer_addr = NULL;
  p_advertising->adv_params.filter_policy = BLE_GAP_ADV_FP_ANY;
  p_advertising->adv_params.interval = p_advertising->adv_modes_config.ble_adv_fast_interval;

  ret = sd_ble_gap_adv_set_configure(&p_advertising->adv_handle, NULL, &p_advertising->adv_params);
  VERIFY_SUCCESS(ret);

  p_advertising->initialized = true;
  return ret;
}