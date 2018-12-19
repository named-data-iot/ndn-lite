/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NRF_SDK_BLE_STACK_H
#define NRF_SDK_BLE_STACK_H

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

/**@brief Structure for callback functions for an observer of the ble stack.
 *
 * @var         on_connected                             See documentation above.
 * @var         on_mtu_rqst                              "                      "
 * @var         on_disconnected                          "                      "
 * @var         on_hvn_tx_complete                       "                      "
 */
typedef struct nrf_sdk_ble_stack_observer_intf {
  on_connected on_connected;
  on_mtu_rqst on_mtu_rqst;
  on_disconnected on_disconnected;
  on_hvn_tx_complete on_hvn_tx_complete;
} nrf_sdk_ble_stack_observer_t ;

/**@brief Initialize the NRF SDK BLE stack.
 */
int nrf_sdk_ble_stack_init();

/**@brief Add an observer to the NRF SDK BLE stack.
 *
 * @param[in]   observer      Observer to add.
 */
int nrf_sdk_ble_stack_add_observer(nrf_sdk_ble_stack_observer_t observer);

/**@brief Returns true if there is currently a connection to a device. Returns false if there is not
 *          currently a connection to a device.
 */
bool nrf_sdk_ble_stack_connected();

#endif // NRF_SDK_BLE_STACK_H