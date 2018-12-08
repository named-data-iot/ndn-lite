/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-nrf-ble-face.h"
#include "../encode/data.h"
#include <stdio.h>

static ndn_nrf_ble_face_t nrf_ble_face;

ndn_nrf_ble_face_t*
ndn_nrf_ble_face_get_instance()
{
  return &nrf_ble_face;
}

/************************************************************/
/*  Inherit Face Interfaces                                 */
/************************************************************/

int
ndn_nrf_ble_face_up(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_UP;
  return 0;
}

int
ndn_nrf_ble_face_send(struct ndn_face_intf* self, const ndn_name_t* name,
                      const uint8_t* packet, uint32_t size)
{

  (void)self;
  (void)name;
  uint8_t packet_block[NDN_NRF_BLE_MAX_PAYLOAD_SIZE];

  // init payload
  if (size <= NDN_NRF_BLE_MAX_PAYLOAD_SIZE) {
    memcpy(packet_block, packet, size);
  }
  else {
    // TBD
    printf("ndn_nrf_ble_face_send failed; size of packet was larger than max payload size.\n");
    return -1;
  }

  if (nrf_sdk_ble_adv_start(packet, size) != NRF_BLE_OP_SUCCESS) {
    printf("nrf_sdk_ble_adv_start failed.\n");
    return -1;
  }
}


int
ndn_nrf_ble_face_down(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DOWN;
  return 0;
}

void
ndn_nrf_ble_face_destroy(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DESTROYED;
  return;
}

void ndn_nrf_ble_received(const uint8_t *p_data, uint8_t length);

ndn_nrf_ble_face_t*
ndn_nrf_ble_face_construct(uint16_t face_id)
{
  // Initialize BLE related things.
  ble_init();

  nrf_sdk_ble_scan_start(ndn_nrf_ble_received);

  nrf_ble_face.intf.up = ndn_nrf_ble_face_up;
  nrf_ble_face.intf.send = ndn_nrf_ble_face_send;
  nrf_ble_face.intf.down = ndn_nrf_ble_face_down;
  nrf_ble_face.intf.destroy = ndn_nrf_ble_face_destroy;
  nrf_ble_face.intf.face_id = face_id;
  nrf_ble_face.intf.state = NDN_FACE_STATE_DESTROYED;
  nrf_ble_face.intf.type = NDN_FACE_TYPE_NET;

  return &nrf_ble_face;
}

//================================================================

void
ndn_nrf_ble_received(const uint8_t *p_data, uint8_t length)
{
  printf("RX frame, payload len %u: \n", (unsigned) length);

  ndn_face_receive(&nrf_ble_face.intf, p_data + NDN_NRF_BLE_ADV_PAYLOAD_HEADER_LENGTH,
                   length - NDN_NRF_BLE_ADV_PAYLOAD_HEADER_LENGTH);
}
