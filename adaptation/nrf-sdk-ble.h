
#ifndef NDN_NRF_BLE_DRIVER_H
#define NDN_NRF_BLE_DRIVER_H

#include "nrf_sdh.h"
#include "nrf_sdh_soc.h"
#include "nrf_sdh_ble.h"
#include "ble.h"
#include "ble_advdata.h"
#include "ble_advertising.h"
#include "nrf_fstorage.h"
#include "nrf_ble_scan.h"

// this include contains parameters for configuring BLE scanning / advertising
#include "nrf-sdk-ble-defs.h"

#define NRF_BLE_OP_FAILURE -1
#define NRF_BLE_OP_SUCCESS 0

// https://devzone.nordicsemi.com/f/nordic-q-a/41180/maximum-amount-of-data-that-can-be-sent-through-extended-advertisements-nrf52840
#define NRF_BLE_EXT_ADV_MAX_PAYLOAD 218

// this is the max amount of advertisements the board will send out when nrf_sdk_ble_adv_start is
// called (if nrf_sdk_ble_adv_start is called again before this number of advertisements is sent, 
//         nrf_sdk_ble_adv_start will send less advertisements than this amount)
#define NRF_BLE_EXT_ADV_BURST_NUM 5// *** 

// function to initialize both the ble stack and the ble scanner
void ble_init();

// this will start BLE advertising and only advertise NRF_BLE_EXT_ADV_BURST_NUM packets 
// before stopping the advertisements if not stopped prematurely by another
// nrf_sdk_ble_adv_start call
int nrf_sdk_ble_adv_start(const uint8_t *payload, uint32_t payload_len);

// starts BLE scanning; will scan for both extended and legacy advertisements
int nrf_sdk_ble_scan_start(void (*scan_callback)(const uint8_t *scan_data, uint8_t scan_data_len));

#endif // NDN_NRF_BLE_DRIVER_H