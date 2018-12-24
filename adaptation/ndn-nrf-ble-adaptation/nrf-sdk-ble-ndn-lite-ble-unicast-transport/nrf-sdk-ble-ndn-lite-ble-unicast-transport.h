/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_TRANSPORT_H
#define NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_TRANSPORT_H

#include <stdint.h>

// ALL FUNCTIONS BELOW THAT RETURN INTEGERS RETURN NRF_BLE_OP_SUCCESS UPON SUCCESS,
// AND NRF_BLE_OP_FAILURE UPON FAILURE.

/**@brief Callback function for a connection event.
 *
 * @param[in]   conn_handle                Handle for the connection.
 */
typedef void (*on_connected)(uint16_t conn_handle);

/**@brief Callback function for an mtu request event.
 *
 * @param[in]   conn_handle                Handle for the connection.
 */
typedef void (*on_mtu_rqst)(uint16_t conn_handle);

/**@brief Callback function for a disconnection event.
 *
 */
typedef void (*on_disconnected)(void);

/**@brief Callback function for a successful notification sent event.
 *
 * @param[in]   conn_handle                Handle for the connection.
 */
typedef void (*on_hvn_tx_complete)(uint16_t conn_handle);

/**@brief Callback function for a received data event.
 *
 * @param[in]   payload                    Pointer to data received.
 * @param[in]   payload_len                Length of payload.
 */
typedef void (*on_recvd_data)(const uint8_t *payload, uint16_t payload_len);

/**@brief Callback function for an advertising stopped event.
 */
typedef void (*on_adv_stopped)();

/**@brief Structure for callback functions for an observer of the nrf sdk ble ndn-lite
            ble unicast transport.
 *
 * @var         on_connected                             See documentation above.
 * @var         on_mtu_rqst                              "                      "
 * @var         on_disconnected                          "                      "
 * @var         on_hvn_tx_complete                       "                      "
 * @var         on_recvd_data                            "                      "
 */
typedef struct nrf_sdk_ble_ndn_lite_ble_unicast_transport_observer_intf {
  on_connected on_connected;
  on_mtu_rqst on_mtu_rqst;
  on_disconnected on_disconnected;
  on_hvn_tx_complete on_hvn_tx_complete;
  on_recvd_data on_recvd_data;
  on_adv_stopped on_adv_stopped;
} nrf_sdk_ble_ndn_lite_ble_unicast_transport_observer_t ;

/**@brief Initialize the transport.
 */
int nrf_sdk_ble_ndn_lite_ble_unicast_transport_init();

/**@brief Send data on the ble unicast connection currently being maintained, if it is available.
 *
 * @param[in]   payload                  The data to include in the "manufacturer specific data" section of the 
 *                                         advertisement packet.
 * @param[in]   payload_len              Length of payload.
 *
 * @retval      NRF_BLE_OP_SUCCESS       There was an active connection, and sending was successful.
 * @retval      NRF_BLE_OP_FAILURE       Either there was no active connection, or sending failed.
 */
int nrf_sdk_ble_ndn_lite_ble_unicast_transport_send(const uint8_t *payload, uint16_t payload_len);

/**@brief Disconnect if there is an active ble unicast connection.
 *
 * @retval      NRF_BLE_OP_SUCCESS       There was an active connection, and disconnection was successful.
 * @retval      NRF_BLE_OP_FAILURE       Either there was no active connection, or disconnection failed.
 */
int nrf_sdk_ble_ndn_lite_ble_unicast_transport_disconnect();

/**@brief Function to start legacy advertising (will advertise the ndn-lite-ble-unicast-service uuid).
 */
int nrf_sdk_ble_ndn_lite_ble_unicast_transport_adv_start();

/**@brief Function to add observer for the transport.
 *
 * @param[in]   observer                 Observer to add for transport.
 */
int nrf_sdk_ble_ndn_lite_ble_unicast_transport_add_observer(
  nrf_sdk_ble_ndn_lite_ble_unicast_transport_observer_t observer);

#endif // NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_TRANSPORT_H