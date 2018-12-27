/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NRF_SDK_BLE_CONN_PARAMS_H
#define NRF_SDK_BLE_CONN_PARAMS_H

// ALL FUNCTIONS BELOW THAT RETURN INTEGERS RETURN NRF_BLE_OP_SUCCESS UPON SUCCESS,
// AND NRF_BLE_OP_FAILURE UPON FAILURE.

/**@brief Function for initializing the Connection Parameters module.
 *
 * @return If this module initialized successfully, or was already initialized successfully
 *           before, will return true. Will return false otherwise.
 */
int nrf_sdk_ble_conn_params_init(void);

#endif // NRF_SDK_BLE_CONN_PARAMS_H