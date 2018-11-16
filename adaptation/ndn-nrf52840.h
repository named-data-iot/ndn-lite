/*
 * Copyright (C) Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NDN_ADAPTATION_NDN_NRF52840_H
#define NDN_ADAPTATION_NDN_NRF52840_H

#include <nrf_802154.h>
#include <forwarder/forwarder.h>

#define NDN_NRF52840_802154_MAX_MESSAGE_SIZE 127
#define NDN_NRF52840_802154_MAX_PAYLOAD_SIZE 102
#define NDN_NRF52840_802154_CHANNEL 23

typedef void (*ndn_on_error_callback_t)(int error_code);

typedef struct ndn_nrf52840_802154_face {
  ndn_face_intf_t intf;

  bool tx_done;
  bool tx_failed;
  nrf_802154_tx_error_t tx_errorcode;

  uint8_t pan_id[2];
  uint8_t short_address[2];

  uint16_t packet_id;
  ndn_on_error_callback_t on_error;
} ndn_nrf52840_802154_face_t;

// there should be only one nrf52840_802154 face
// use this function to get the singleton instance
// if the instance has not been initialized,
// use ndn_nrf52840_802154_face_construct instead
ndn_nrf52840_802154_face_t*
ndn_nrf52840_init_802154_get_face_instance();


ndn_nrf52840_802154_face_t*
ndn_nrf52840_802154_face_construct(uint16_t face_id, const uint8_t* extended_address,
                                   const uint8_t* pan_id, const uint8_t* short_address,
                                   bool promisc, ndn_on_error_callback_t error_callback);

#endif // NDN_ADAPTATION_NDN_NRF52840_H
