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

#ifndef NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_H
#define NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_H

#include "ble.h"
#include "ble_srv_common.h"
#include "boards.h"
#include "nrf_sdh_ble.h"
#include <stdint.h>

/**@brief   Macro for defining a NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE instance.
 *
 * @param   _name   Name of the instance.
 * @hideinitializer
 */

#define NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_BLE_OBSERVER_PRIO 2

#define NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_DEF(_name)       \
  static nrf_sdk_ble_ndn_lite_ble_unicast_service_t _name;        \
  NRF_SDH_BLE_OBSERVER(_name##_obs,                   \
      NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_BLE_OBSERVER_PRIO, \
      nrf_sdk_ble_ndn_lite_ble_unicast_service_on_ble_evt, &_name)

// The bytes are stored in little-endian format, meaning the
// Least Significant Byte is stored first
// (reversed from the order they're displayed as)

// Secure Sign On Service Base UUID: E54B0000-67F5-479E-8711-B3B99198CE6C
#define BLE_UUID_NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_BASE_UUID \
  { 0x6C, 0xCE, 0x98, 0x91, 0xB9, 0xB3, 0x11, 0x87, 0x9E, 0x47, 0xF5, 0x67, 0x00, 0x00, 0x4B, 0xE5 }
// Data Transfer Characteristic Base UUID: 0E1524FD-760F-439A-A15D-A2CAD8973D15
#define BLE_UUID_DATA_TRANSFER_CHARACTERISTIC_BASE_UUID \
  { 0x15, 0x3D, 0x97, 0xD8, 0xCA, 0xA2, 0x5D, 0xA1, 0x9A, 0x43, 0x0F, 0x76, 0x00, 0x00, 0x15, 0x0E }

// Service & characteristics UUIDs
#define BLE_UUID_NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_UUID_OFFSET 0x0000
#define BLE_UUID_DATA_TRANSFER_CHAR_UUID_OFFSET 0x24FD

// Forward declaration of the custom_service_t type.
typedef struct nrf_sdk_ble_ndn_lite_ble_unicast_service_s nrf_sdk_ble_ndn_lite_ble_unicast_service_t;

typedef void (*nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler_t)(
                                uint16_t conn_handle, 
                                nrf_sdk_ble_ndn_lite_ble_unicast_service_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p, 
                                const uint8_t *received_data, uint16_t data_len);

typedef ret_code_t (*nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification_t)(
                                uint16_t conn_handle, 
                                nrf_sdk_ble_ndn_lite_ble_unicast_service_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p, 
                                uint8_t *write_data, uint16_t *data_len);

/** @brief ndn-lite ble unicast Service init structure. This structure contains all options and data needed for
 *        initialization of the service.*/
typedef struct
{
  /**< Event handler to be called when the ndn-lite ble unicast Characteristic is written. */
  nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler_t nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler;
  nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification_t nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification;
} nrf_sdk_ble_ndn_lite_ble_unicast_service_init_t;

/**@brief ndn-lite ble unicast Service structure.
 *        This contains various status information
 *        for the service.
 */
typedef struct nrf_sdk_ble_ndn_lite_ble_unicast_service_s {
  uint16_t conn_handle;
  uint16_t service_handle;
  uint8_t uuid_type;
  ble_gatts_char_handles_t data_transfer_char_handles;
  nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler_t nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_write_handler;
  nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification_t nrf_sdk_ble_ndn_lite_ble_unicast_service_data_transfer_send_notification;
} nrf_sdk_ble_ndn_lite_ble_unicast_service_t;

// Function Declarations

/**@brief Function for initializing the ndn-lite ble unicast Service.
 *
 * @param[out]  nrf_sdk_ble_ndn_lite_ble_unicast_service_p  ndn-lite ble unicast Service structure. This structure will have to be supplied by
 *                                the application. It will be initialized by this function, and will later
 *                                be used to identify this particular service instance.
 *
 * @return      NRF_SUCCESS on successful initialization of service, otherwise an error code.
 */
uint32_t nrf_sdk_ble_ndn_lite_ble_unicast_service_init(nrf_sdk_ble_ndn_lite_ble_unicast_service_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_p,
    const nrf_sdk_ble_ndn_lite_ble_unicast_service_init_t *nrf_sdk_ble_ndn_lite_ble_unicast_service_init_p);

/**@brief Function for handling the application's BLE stack events.
 *
 * @details This function handles all events from the BLE stack that are of interest to the ndn-lite ble unicast Service.
 *
 * @param[in] p_ble_evt  Event received from the BLE stack.
 * @param[in] p_context  ndn-lite ble unicast Service structure.
 */
void nrf_sdk_ble_ndn_lite_ble_unicast_service_on_ble_evt(ble_evt_t const *p_ble_evt, void *p_context);

#endif /* NRF_SDK_BLE_NDN_LITE_BLE_UNICAST_SERVICE_H */