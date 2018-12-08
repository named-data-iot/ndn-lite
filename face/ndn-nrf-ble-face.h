
#ifndef NDN_NRF_BLE_FACE_H
#define NDN_NRF_BLE_FACE_H

#include "../forwarder/forwarder.h"

#include "../adaptation/nrf-sdk-ble.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NDN_NRF_BLE_MAX_PAYLOAD_SIZE (NRF_BLE_EXT_ADV_MAX_PAYLOAD)

#define NDN_NRF_BLE_ADV_PAYLOAD_HEADER_LENGTH 20

typedef void (*ndn_on_error_callback_t)(int error_code);

typedef struct ndn_nrf_ble_face {
  ndn_face_intf_t intf;
} ndn_nrf_ble_face_t;

// there should be only one nrf_ble face
// use this function to get the singleton instance
// if the instance has not been initialized,
// use ndn_nrf_ble_face_construct instead
ndn_nrf_ble_face_t*
ndn_nrf_init_ble_get_face_instance();

ndn_nrf_ble_face_t*
ndn_nrf_ble_face_construct(uint16_t face_id);

#ifdef __cplusplus
}
#endif

#endif // NDN_NRF_BLE_FACE_H