/*
 * Copyright (C) Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

/***********************************************************
 **  This Face Implementation depends on the adaptation of
 **  nRF-IEEE-802.15.4-radio-driver provided by Nordic
 **
 **  If you are not using nRF-IEEE-802.15.4-radio-driver, please
 **  do not include this header with its source file into your
 **  project.
 ************************************************************/

#ifndef NDN_FACE_NRF_802154_FACE_H
#define NDN_FACE_NRF_802154_FACE_H

#include "../adaptation/ndn-nrf-802154-driver.h"
#include "../forwarder/forwarder.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NDN_NRF_802154_MAX_MESSAGE_SIZE 50
#define NDN_NRF_802154_MAX_PAYLOAD_SIZE 50
#define NDN_NRF_802154_CHANNEL 23

typedef void (*ndn_on_error_callback_t)(int error_code);

typedef struct ndn_nrf_802154_face {
  ndn_face_intf_t intf;

  bool tx_done;
  bool tx_failed;
  nrf_802154_tx_error_t tx_errorcode;

  uint8_t pan_id[2];
  uint8_t short_address[2];

  uint16_t packet_id;
  ndn_on_error_callback_t on_error;
} ndn_nrf_802154_face_t;

// there should be only one nrf_802154 face
// use this function to get the singleton instance
// if the instance has not been initialized,
// use ndn_nrf_802154_face_construct instead
ndn_nrf_802154_face_t*
ndn_nrf_init_802154_get_face_instance();


ndn_nrf_802154_face_t*
ndn_nrf_802154_face_construct(uint16_t face_id, const uint8_t* extended_address,
                              const uint8_t* pan_id, const uint8_t* short_address,
                              bool promisc, ndn_on_error_callback_t error_callback);

#ifdef __cplusplus
}
#endif

#endif // NDN_FACE_NRF_802154_FACE_H
