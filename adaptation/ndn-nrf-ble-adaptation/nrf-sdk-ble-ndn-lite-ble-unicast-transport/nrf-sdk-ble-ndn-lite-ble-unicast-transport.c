/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "nrf-sdk-ble-ndn-lite-ble-unicast-transport.h"

#include "nrf_ble_qwr.h"

#include "../nrf-sdk-ble-conn-params/nrf-sdk-ble-conn-params.h"
#include "../nrf-sdk-ble-advertising/nrf-sdk-ble-adv.h"
#include "../nrf-sdk-ble-gap/nrf-sdk-ble-gap.h"
#include "../nrf-sdk-ble-gatt/nrf-sdk-ble-gatt.h"
#include "../nrf-sdk-ble-stack/nrf-sdk-ble-stack.h"
#include "nrf-sdk-ble-ndn-lite-ble-unicast-service.h"

#include "nrf-sdk-ble-ndn-lite-ble-unicast-transport-defs.h"

#include "../nrf-sdk-ble-error-check.h"
#include "../nrf-sdk-ble-consts.h"

#include "../nrf-logger.h"

NRF_BLE_QWR_DEF(m_qwr); /**< Context for the Queued Write module.*/
uint16_t m_conn_handle = BLE_CONN_HANDLE_INVALID; /**< Handle of the current connection. */
ble_uuid_t m_ndn_lite_ble_unicast_service_uuid; /**< Uuid of ndn lite ble unicast service. */
/**< Structure used to identify the ndn lite ble unicast service. */
NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_DEF(m_nrf_sdk_ble_ndn_lite_ble_unicast_service);
/**< An array of observers. */
nrf_sdk_ble_ndn_lite_ble_unicast_transport_observer_t 
  m_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers[NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_TRANSPORT_MAX_OBSERVERS];
int m_num_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers = 0; /**< Current number of observers. */
static bool m_init_success = false; /**< Will be true if this module was already initialized successfully. */


ret_code_t sendPacket(uint16_t conn_handle, nrf_sdk_ble_ndn_lite_ble_unicast_service_t *ndn_lite_ble_unicast_service_p, uint8_t *cert_rqst_buf, uint16_t *cert_rqst_buf_len_p);

void on_advertising_stopped(void) {
  NRF_APP_LOG("on_advertising_stopped in nrf-sdk-ble-transport got called\n");

  for (int i = 0; i < m_num_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers; i++) {
    m_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers[i].on_adv_stopped();
  }
}

int nrf_sdk_ble_ndn_lite_ble_unicast_transport_adv_start() {
  m_ndn_lite_ble_unicast_service_uuid.uuid = 0x0000;
  m_ndn_lite_ble_unicast_service_uuid.type = m_nrf_sdk_ble_ndn_lite_ble_unicast_service.uuid_type;

  return nrf_sdk_ble_adv_start(NULL, 0, m_ndn_lite_ble_unicast_service_uuid, false, 
                               NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_TRANSPORT_ADV_START_NUM_ADVS, 
                               on_advertising_stopped);
}

void recvd_data_callback(const uint8_t *data_recvd_p, uint16_t data_recvd_len) {
  NRF_APP_LOG("recvd_data_callback got called.\n");
  NRF_APP_LOG_HEX("Received data:", data_recvd_p, data_recvd_len);

  for (int i = 0; i < m_num_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers; i++) {
    m_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers[i].on_recvd_data(data_recvd_p, data_recvd_len);
  }
}

void got_connected_callback(uint16_t conn_handle) {
  NRF_APP_LOG("got_connected_callback got called inside of nrf-sdk-ble-transport.\n");

  NRF_APP_LOG("Value of conn_handle in the got_connected_callback: %d\n", conn_handle);

  for (int i = 0; i < m_num_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers; i++) {
    m_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers[i].on_connected(conn_handle);
  }

  ret_code_t err_code;

  m_conn_handle = conn_handle;
  err_code = nrf_ble_qwr_conn_handle_assign(&m_qwr, m_conn_handle);
  APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "nrf-sdk-ble-transport.c, got_connected_callback, nrf_ble_qwr_conn_handle_assign");

}

void got_disconnected_callback() {
  NRF_APP_LOG("got_disconnected_callback got called.\n");

  nrf_sdk_ble_adv_stop();

  for (int i = 0; i < m_num_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers; i++) {
    m_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers[i].on_disconnected();
  }
}

void got_mtu_rqst_callback(uint16_t conn_handle) {
  NRF_APP_LOG("got_mtu_rqst_callback got called.\n");

  NRF_APP_LOG("Value of got_mtu_rqst_callback: %d\n", conn_handle);

  for (int i = 0; i < m_num_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers; i++) {
    m_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers[i].on_mtu_rqst(conn_handle);
  }
}

void got_hvn_tx_complete_callback(uint16_t conn_handle) {
  NRF_APP_LOG("got_hvn_tx_complete_callback got called.\n");

  for (int i = 0; i < m_num_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers; i++) {
    m_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers[i].on_hvn_tx_complete(conn_handle);
  }
}

ret_code_t nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification(uint16_t conn_handle,
    nrf_sdk_ble_ndn_lite_ble_unicast_service_t *ndn_lite_ble_unicast_service_p,
    uint8_t *write_data, uint16_t *data_len) {
  if (conn_handle != BLE_CONN_HANDLE_INVALID) {

    ret_code_t err_code;

    ble_gatts_hvx_params_t hvx_params;
    memset(&hvx_params, 0, sizeof(hvx_params));

    hvx_params.handle = ndn_lite_ble_unicast_service_p->data_transfer_char_handles.value_handle;
    hvx_params.type = BLE_GATT_HVX_NOTIFICATION;
    hvx_params.offset = 0;
    hvx_params.p_len = data_len;
    hvx_params.p_data = write_data;

    err_code = sd_ble_gatts_hvx(conn_handle, &hvx_params);
    if (err_code != NRF_SUCCESS)
      return err_code;

    return NRF_SUCCESS;
  }
}

ret_code_t sendPacket(uint16_t conn_handle, nrf_sdk_ble_ndn_lite_ble_unicast_service_t *ndn_lite_ble_unicast_service,
    uint8_t *cert_rqst_buf, uint16_t *cert_rqst_buf_len_p) {

  NRF_APP_LOG("Send packet got called, bytes being sent:\n");
  NRF_APP_LOG_HEX("Bytes being sent in sendPacket in nrf-sdk-ble-transport", cert_rqst_buf, *cert_rqst_buf_len_p);

  return nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification(conn_handle, ndn_lite_ble_unicast_service,
      cert_rqst_buf, cert_rqst_buf_len_p);
}

/**@brief Function for handling Queued Write Module errors.
 *
 * @details A pointer to this function will be passed to each service which may need to inform the
 *          application about an error.
 *
 * @param[in]   nrf_error   Error code containing information about what went wrong.
 */
static void nrf_qwr_error_handler(uint32_t nrf_error) {
  APP_ERROR_CHECK_IGNORE_INVALID_STATE(nrf_error, "nrf-sdk-ble-transport.c,nrf_qwr_error_handler");
}

/**@brief Function for handling write events to the data transfer characteristic.
 *
 * @param[in] p_secure_sign_on_ble_service  Instance of secure_sign_on Service to which the write applies.
 * @param[in] write_data                Data we received.
 */
static void nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler(uint16_t conn_handle, 
                    nrf_sdk_ble_ndn_lite_ble_unicast_service_t *ndn_lite_ble_unicast_service_p,
    const uint8_t *received_data, uint16_t data_len) {
  NRF_APP_LOG("In ndn_lite_ble_unicast_service_data_transfer_write, got write of length %d\n", data_len);
  NRF_APP_LOG_HEX("Data of write:", received_data, data_len);

  recvd_data_callback(received_data, data_len);
}

/**@brief Function for initializing services that will be used by the application.
 */
int nrf_sdk_ble_ndn_lite_ble_unicast_transport_nrf_ble_qwr_init() {
  ret_code_t err_code;
  nrf_ble_qwr_init_t qwr_init = {0};

  // Initialize Queued Write Module.
  qwr_init.error_handler = nrf_qwr_error_handler;

  err_code = nrf_ble_qwr_init(&m_qwr, &qwr_init);
  APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "nrf-sdk-ble-transport.c,services_init, nrf_ble_qwr_init");
  return err_code;

}

int nrf_sdk_ble_ndn_lite_ble_unicast_transport_ndn_lite_ble_unicast_service_init(nrf_sdk_ble_ndn_lite_ble_unicast_service_t 
  *nrf_sdk_ble_ndn_lite_ble_unicast_service_p) {

  ret_code_t err_code;

  nrf_sdk_ble_ndn_lite_ble_unicast_service_init_t nrf_sdk_ble_ndn_lite_ble_unicast_service_init_object;

  // 1. Initialize the secure_sign_on service
  nrf_sdk_ble_ndn_lite_ble_unicast_service_init_object.nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler = nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler;
  nrf_sdk_ble_ndn_lite_ble_unicast_service_init_object.nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification = nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification;

  err_code = nrf_sdk_ble_ndn_lite_ble_unicast_service_init(nrf_sdk_ble_ndn_lite_ble_unicast_service_p, &nrf_sdk_ble_ndn_lite_ble_unicast_service_init_object);
  APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "nrf-sdk-ble-transport.c,services_init, ndn_lite_ble_unicast_service_init");
  return err_code;
}

/**@brief Function for putting the chip into sleep mode.
 *
 * @note This function will not return.
 */
static void sleep_mode_enter(void) {
  ret_code_t err_code;

  // Go to system-off mode (this function will not return; wakeup will cause a reset).
  err_code = sd_power_system_off();
  APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "nrf-sdk-ble-transport.c, sleep_mode_enter, sd_power_system_off");
}

int nrf_sdk_ble_ndn_lite_ble_unicast_transport_init() {

  if (m_init_success)
    return NRF_BLE_OP_SUCCESS;

  if (nrf_sdk_ble_stack_init() != NRF_BLE_OP_SUCCESS) {
    NRF_APP_LOG("in nrf_sdk_ble_ndn_lite_ble_unicast_transport_init, nrf_sdk_ble_stack_init failed.\n");
    return NRF_BLE_OP_FAILURE;
  }
  
  nrf_sdk_ble_stack_observer_t observer;
  observer.on_connected = got_connected_callback;
  observer.on_disconnected = got_disconnected_callback;
  observer.on_mtu_rqst = got_mtu_rqst_callback;
  observer.on_hvn_tx_complete = got_hvn_tx_complete_callback;
  nrf_sdk_ble_stack_add_observer(observer);

  if (nrf_sdk_ble_gap_init() != NRF_BLE_OP_SUCCESS) {
    NRF_APP_LOG("in nrf_sdk_ble_ndn_lite_ble_unicast_transport_init, nrf_sdk_ble_gap_init.\n");
    return NRF_BLE_OP_FAILURE;
  }
  if (nrf_sdk_ble_gatt_init() != NRF_BLE_OP_SUCCESS) {
    NRF_APP_LOG("in nrf_sdk_ble_ndn_lite_ble_unicast_transport_init, nrf_sdk_ble_gatt_init.\n");
    return NRF_BLE_OP_FAILURE;
  }
  // make sure services are initialized before advertising for custom UUID, according to
  // https://devzone.nordicsemi.com/f/nordic-q-a/15153/proper-setup-of-m_adv_uuids-for-custom-service
  if (nrf_sdk_ble_ndn_lite_ble_unicast_transport_nrf_ble_qwr_init() != NRF_SUCCESS) {
    NRF_APP_LOG("in nrf_sdk_ble_ndn_lite_ble_unicast_transport_init, nrf_sdk_ble_ndn_lite_ble_unicast_transport_nrf_ble_qwr_init failed.\n");
    return NRF_BLE_OP_FAILURE;
  }
  if (nrf_sdk_ble_ndn_lite_ble_unicast_transport_ndn_lite_ble_unicast_service_init(
      &m_nrf_sdk_ble_ndn_lite_ble_unicast_service) != NRF_SUCCESS) {
        NRF_APP_LOG("in nrf_sdk_ble_ndn_lite_ble_unicast_transport_init, nrf_sdk_ble_ndn_lite_ble_unicast_transport_ndn_lite_ble_unicast_service_init failed.\n");
    return NRF_BLE_OP_FAILURE;
  }
  if (nrf_sdk_ble_conn_params_init() != NRF_BLE_OP_SUCCESS) {
    NRF_APP_LOG("in nrf_sdk_ble_ndn_lite_ble_unicast_transport_init, nrf_sdk_ble_conn_params_init.\n");
    return NRF_BLE_OP_FAILURE;
  }

  if (nrf_sdk_ble_ndn_lite_ble_unicast_transport_adv_start() != NRF_BLE_OP_SUCCESS) {
    NRF_APP_LOG("in nrf_sdk_ble_ndn_lite_ble_unicast_transport_init, nrf_sdk_ble_ndn_lite_ble_unicast_transport_adv_start failed.\n");
    return NRF_BLE_OP_FAILURE;
  }

  m_init_success = true;

  return NRF_BLE_OP_SUCCESS;
}

int nrf_sdk_ble_ndn_lite_ble_unicast_transport_disconnect() {

  if (nrf_sdk_ble_stack_connected() == true) {
    NRF_APP_LOG("ndn_lite_ble_unicast_transport_disconnect was called, and we were connected.\n");
    ret_code_t err_code = sd_ble_gap_disconnect(m_conn_handle,
        BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
    if (err_code != NRF_ERROR_INVALID_STATE && err_code != NRF_SUCCESS) {
      APP_ERROR_CHECK_IGNORE_INVALID_STATE(err_code, "nrf-sdk-ble-transport.c, ndn_lite_ble_unicast_transport_disconnect, sd_ble_gap_disconnect");
    }
  } else {
    NRF_APP_LOG("ndn_lite_ble_unicast_transport_disconnect was called, but we were not connected.\n");
    return NRF_BLE_OP_FAILURE;
  }

  return NRF_BLE_OP_SUCCESS;
}

int nrf_sdk_ble_ndn_lite_ble_unicast_transport_add_observer(
  nrf_sdk_ble_ndn_lite_ble_unicast_transport_observer_t observer) {

  m_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers[m_num_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers++] =
    observer;
  NRF_APP_LOG("Current number of observers in nrf_sdk_ble_ndn_lite_ble_unicast_transport: %d\n", 
    m_num_nrf_sdk_ble_ndn_lite_ble_unicast_transport_observers);

  return NRF_BLE_OP_SUCCESS;
}

int nrf_sdk_ble_ndn_lite_ble_unicast_transport_send(const uint8_t *payload, uint16_t payload_len) {
  ret_code_t err_code;
  NRF_APP_LOG("ndn_lite_ble_unicast_transport_send got called\n");
  if (nrf_sdk_ble_stack_connected()) {
    NRF_APP_LOG("in ndn_lite_ble_unicast_transport_send, nrf_sdk_ble_stack_connected was true\n");
    err_code = sendPacket(m_conn_handle, &m_nrf_sdk_ble_ndn_lite_ble_unicast_service, payload, &payload_len);
    return err_code;
  }
  else {
    return NRF_BLE_OP_FAILURE;
  }
}