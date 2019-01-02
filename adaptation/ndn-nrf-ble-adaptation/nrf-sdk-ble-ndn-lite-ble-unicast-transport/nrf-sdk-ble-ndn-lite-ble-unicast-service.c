
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

// adapted from example code given here: https://www.novelbits.io/smart-ble-lightbulb-application-nrf52/

#include <string.h>

//#include "../../../../sdk_config.h"
#include "nrf-sdk-ble-ndn-lite-ble-unicast-service.h"
#include "../logger.h"

static const uint8_t DataTransferCharName[] = "Data Transfer";

/**@brief Function for handling the Connect event.
 *
 * @param[in]   nrf_sdk_ble_ndn_lite_ble_unicast_service_p  secure_sign_on service structure.
 * @param[in]   p_ble_evt      Event received from the BLE stack.
 */
static void on_connect(nrf_sdk_ble_ndn_lite_ble_unicast_service_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p, ble_evt_t const *p_ble_evt) {
  nrf_sdk_ble_ndn_lite_ble_unicast_service_p->conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
}

/**@brief Function for handling the Disconnect event.
 *
 * @param[in]   p_bas       secure_sign_on service structure.
 * @param[in]   p_ble_evt   Event received from the BLE stack.
 */
static void on_disconnect(nrf_sdk_ble_ndn_lite_ble_unicast_service_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p, ble_evt_t const *p_ble_evt) {
  UNUSED_PARAMETER(p_ble_evt);
  nrf_sdk_ble_ndn_lite_ble_unicast_service_p->conn_handle = BLE_CONN_HANDLE_INVALID;
}

/**@brief Function for handling the Write event.
 *
 * @param[in] nrf_sdk_ble_ndn_lite_ble_unicast_service_p   secure_sign_on Service structure.
 * @param[in] p_ble_evt       Event received from the BLE stack.
 */
static void on_write(nrf_sdk_ble_ndn_lite_ble_unicast_service_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p, ble_evt_t const *p_ble_evt) {
  ble_gatts_evt_write_t const *p_evt_write = &p_ble_evt->evt.gatts_evt.params.write;

  if ((p_evt_write->handle == nrf_sdk_ble_ndn_lite_ble_unicast_service_p->data_transfer_char_handles.value_handle) && (nrf_sdk_ble_ndn_lite_ble_unicast_service_p->nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler != NULL)) {
    //APP_LOG("Calling secure_sign_on_write_handler in on_write");
    nrf_sdk_ble_ndn_lite_ble_unicast_service_p->nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler(p_ble_evt->evt.gap_evt.conn_handle,
        nrf_sdk_ble_ndn_lite_ble_unicast_service_p, p_evt_write->data, p_evt_write->len);
  } else {
    APP_LOG("Did not call secure_sign_on_write_handler in on_write\n");
    APP_LOG_HEX("Data that got written:", p_evt_write->data, p_evt_write->len);
  }
}

/**@brief Function for adding the secure_sign_on 2 characteristic.
 *
 */
static uint32_t data_transfer_char_add(nrf_sdk_ble_ndn_lite_ble_unicast_service_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p) {
  ble_gatts_char_md_t char_md;
  ble_gatts_attr_t attr_char_value;
  ble_gatts_attr_md_t attr_md;
  ble_gatts_attr_md_t cccd_md; // declaring the client characteristic configuration descriptor

  memset(&char_md, 0, sizeof(char_md));
  memset(&attr_md, 0, sizeof(attr_md));
  memset(&attr_char_value, 0, sizeof(attr_char_value));
  memset(&cccd_md, 0, sizeof(cccd_md));

  // see https://devzone.nordicsemi.com/f/nordic-q-a/21601/can-i-create-characteristic-with-notification-only-no-read-no-write
  BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
  BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);

  cccd_md.vloc = BLE_GATTS_VLOC_STACK;

  char_md.char_props.read = 1;
  char_md.char_props.write = 1;
  char_md.char_props.notify = 1;
  char_md.p_char_user_desc = DataTransferCharName;
  char_md.char_user_desc_size = sizeof(DataTransferCharName);
  char_md.char_user_desc_max_size = sizeof(DataTransferCharName);
  char_md.p_char_pf = NULL;
  char_md.p_user_desc_md = NULL;
  char_md.p_cccd_md = &cccd_md;
  //char_md.p_cccd_md                = NULL;
  char_md.p_sccd_md = NULL;

  // Define the data transfer Characteristic UUID
  ble_uuid_t data_transfer_char_uuid;
  data_transfer_char_uuid.uuid = BLE_UUID_DATA_TRANSFER_CHAR_UUID_OFFSET;
  ble_uuid128_t data_transfer_char_uuid_base = {BLE_UUID_DATA_TRANSFER_CHARACTERISTIC_BASE_UUID};
  data_transfer_char_uuid.type = nrf_sdk_ble_ndn_lite_ble_unicast_service_p->uuid_type;
  sd_ble_uuid_vs_add(&data_transfer_char_uuid_base, &data_transfer_char_uuid.type);

  // Set permissions on the Characteristic value
  BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
  BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);

  // Attribute Metadata settings
  attr_md.vloc = BLE_GATTS_VLOC_STACK;
  attr_md.vlen = 1;
  attr_md.rd_auth = 0;
  attr_md.wr_auth = 0;
  attr_md.vlen = 0;

  // Attribute Value settings
  attr_char_value.p_uuid = &data_transfer_char_uuid;
  attr_char_value.p_attr_md = &attr_md;
  attr_char_value.init_len = 510;
  attr_char_value.init_offs = 0;
  attr_char_value.max_len = 510;
  attr_char_value.p_value = NULL;

  return sd_ble_gatts_characteristic_add(nrf_sdk_ble_ndn_lite_ble_unicast_service_p->service_handle, &char_md,
      &attr_char_value,
      &nrf_sdk_ble_ndn_lite_ble_unicast_service_p->data_transfer_char_handles);
}

uint32_t nrf_sdk_ble_ndn_lite_ble_unicast_service_init(nrf_sdk_ble_ndn_lite_ble_unicast_service_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p,
    const nrf_sdk_ble_ndn_lite_ble_unicast_service_init_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p_init) {
  uint32_t err_code;
  ble_uuid_t ble_uuid;

  // Initialize service structure
  nrf_sdk_ble_ndn_lite_ble_unicast_service_p->conn_handle = BLE_CONN_HANDLE_INVALID;

  // Initialize service structure.
  nrf_sdk_ble_ndn_lite_ble_unicast_service_p->nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler = nrf_sdk_ble_ndn_lite_ble_unicast_service_p_init->nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler;
  nrf_sdk_ble_ndn_lite_ble_unicast_service_p->nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification = nrf_sdk_ble_ndn_lite_ble_unicast_service_p_init->nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification;

  // Add service UUID
  ble_uuid128_t base_uuid = {BLE_UUID_NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_BASE_UUID};
  err_code = sd_ble_uuid_vs_add(&base_uuid, &nrf_sdk_ble_ndn_lite_ble_unicast_service_p->uuid_type);
  if (err_code != NRF_SUCCESS) {
    return err_code;
  }

  // Set up the UUID for the service (base + service-specific)
  ble_uuid.type = nrf_sdk_ble_ndn_lite_ble_unicast_service_p->uuid_type;
  ble_uuid.uuid = BLE_UUID_NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_UUID_OFFSET;

  // Set up and add the service
  err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &ble_uuid, &nrf_sdk_ble_ndn_lite_ble_unicast_service_p->service_handle);
  if (err_code != NRF_SUCCESS) {
    return err_code;
  }

  // Add the different characteristics in the service:
  //   Button press characteristic:   E54B0002-67F5-479E-8711-B3B99198CE6C
  err_code = data_transfer_char_add(nrf_sdk_ble_ndn_lite_ble_unicast_service_p);
  if (err_code != NRF_SUCCESS) {
    return err_code;
  }

  return NRF_SUCCESS;
}

void nrf_sdk_ble_ndn_lite_ble_unicast_service_on_ble_evt(ble_evt_t const *p_ble_evt, void *p_context) {
  nrf_sdk_ble_ndn_lite_ble_unicast_service_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p = (nrf_sdk_ble_ndn_lite_ble_unicast_service_t *)p_context;

  switch (p_ble_evt->header.evt_id) {
  case BLE_GAP_EVT_CONNECTED:
    on_connect(nrf_sdk_ble_ndn_lite_ble_unicast_service_p, p_ble_evt);
    break;

  case BLE_GATTS_EVT_WRITE:
    // APP_LOG("Got a BLE_GATTS_EVT_WRITE event.");
    // APP_LOG("Length of data written: %d", p_ble_evt->evt.gatts_evt.params.write.len);
    on_write(nrf_sdk_ble_ndn_lite_ble_unicast_service_p, p_ble_evt);
    break;

  case BLE_GAP_EVT_DISCONNECTED:
    on_disconnect(nrf_sdk_ble_ndn_lite_ble_unicast_service_p, p_ble_evt);
    break;

  default:
    // No implementation needed.
    break;
  }
}