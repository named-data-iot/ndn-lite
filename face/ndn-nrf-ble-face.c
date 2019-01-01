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

#include "nrf_delay.h"

#include "../adaptation/ndn-nrf-ble-adaptation/nrf-sdk-ble-advertising/nrf-sdk-ble-adv.h"
#include "../adaptation/ndn-nrf-ble-adaptation/nrf-sdk-ble-consts.h"
#include "../adaptation/ndn-nrf-ble-adaptation/nrf-sdk-ble-ndn-lite-ble-unicast-transport/nrf-sdk-ble-ndn-lite-ble-unicast-transport.h"
#include "../adaptation/ndn-nrf-ble-adaptation/nrf-sdk-ble-scanning/nrf-sdk-ble-scan.h"
#include "../adaptation/ndn-nrf-ble-adaptation/nrf-sdk-ble-stack/nrf-sdk-ble-stack.h"

void ndn_nrf_ble_adv_stopped(void);
void ndn_nrf_ble_unicast_disconnected(void);
void ndn_nrf_ble_unicast_connected(uint16_t conn_handle);
void ndn_nrf_ble_unicast_on_mtu_rqst(uint16_t conn_handle);
void ndn_nrf_ble_unicast_hvn_tx_complete(uint16_t conn_handle);

static ndn_nrf_ble_face_t nrf_ble_face;

ble_uuid_t ndn_nrf_ble_face_adv_uuid = {NDN_LITE_BLE_EXT_ADV_UUID, BLE_UUID_TYPE_BLE};

uint8_t current_packet_block_to_send[NDN_NRF_BLE_MAX_PAYLOAD_SIZE];
uint8_t *current_packet_block_to_send_p = NULL;
uint32_t current_packet_block_to_send_size = 0;

ndn_nrf_ble_face_t *
ndn_nrf_ble_face_get_instance() {
  return &nrf_ble_face;
}

/************************************************************/
/*  Inherit Face Interfaces                                 */
/************************************************************/

int ndn_nrf_ble_face_up(struct ndn_face_intf *self) {
  self->state = NDN_FACE_STATE_UP;
  return 0;
}

int ndn_nrf_ble_send_unicast_packet(const char *msg);
int ndn_nrf_ble_send_extended_adv_packet(const char *msg);

int ndn_nrf_ble_face_send(struct ndn_face_intf *self, const ndn_name_t *name,
    const uint8_t *packet, uint32_t size) {

  printf("ndn_nrf_ble_face_send got called. \n");

  (void)self;
  (void)name;
  uint8_t packet_block[NDN_NRF_BLE_MAX_PAYLOAD_SIZE];

  if (current_packet_block_to_send_p != NULL) {
    printf("in ndn_nrf_ble_face_send, current_packet_block_to_send_p wasn't NULL, "
           "meaning we are currently sending something else\n");
    return -1;
  }

  // init payload
  if (!(size <= NDN_NRF_BLE_MAX_PAYLOAD_SIZE)) {
    // TBD
    printf("ndn_nrf_ble_face_send failed; size of packet was larger than max payload size.\n");
    return -1;
  }

  // remember what packet we are currently trying to send
  current_packet_block_to_send_p = &current_packet_block_to_send[0];
  memcpy(current_packet_block_to_send, packet, size);
  current_packet_block_to_send_size = size;

  // as soon as someone requests to send data, we send to the controller, and then
  // disconnect to do extended advertising with the same data packet, then reconnect to the controller
  // afterwards

  if (nrf_sdk_ble_stack_connected()) {
    printf("in ndn_nrf_ble_face_send, we were connected.\n");
    if (!ndn_nrf_ble_send_unicast_packet("in ndn_nrf_ble_face_send, "
                                    "ndn_lite_ble_unicast_transport_send failed.\n")) {
      if (!ndn_nrf_ble_send_extended_adv_packet("in ndn_nrf_ble_face_send, "
                                           "calling ndn_nrf_ble_send_extended_adv_packet "
                                           "failed, so calling "
                                            "ndn_nrf_ble_send_extended_adv_packet\n")) {
        printf("in ndn_nrf_ble_face_send, both ndn_nrf_ble_send_unicast_packet and "
               "ndn_nrf_ble_send_extended_adv_packet failed\n");
      }
    }
  } else {
    printf("in ndn_nrf_ble_face_send, we were not connected.\n");
    ndn_nrf_ble_send_extended_adv_packet("nrf_sdk_ble_adv_start inside of "
                                         "ndn_nrf_ble_adv_stopped failed.\n");
  }

  return 0;
}

int ndn_nrf_ble_face_down(struct ndn_face_intf *self) {
  self->state = NDN_FACE_STATE_DOWN;
  return 0;
}

void ndn_nrf_ble_face_destroy(struct ndn_face_intf *self) {
  self->state = NDN_FACE_STATE_DESTROYED;
  return;
}

void ndn_nrf_ble_recvd_data_ext_adv(const uint8_t *p_data, uint8_t length);
void ndn_nrf_ble_recvd_data_unicast(const uint8_t *p_data, uint16_t length);
void ndn_nrf_ble_legacy_adv_stopped();

ndn_nrf_ble_face_t *
ndn_nrf_ble_face_construct(uint16_t face_id) {
  // Initialize BLE related things.
  nrf_sdk_ble_stack_init();

  nrf_sdk_ble_scan_init(ndn_nrf_ble_face_adv_uuid);
  nrf_sdk_ble_scan_start(ndn_nrf_ble_recvd_data_ext_adv);

  nrf_sdk_ble_ndn_lite_ble_unicast_transport_init();
  nrf_sdk_ble_ndn_lite_ble_unicast_transport_observer_t observer;
  observer.on_connected = ndn_nrf_ble_unicast_connected;
  observer.on_disconnected = ndn_nrf_ble_unicast_disconnected;
  observer.on_hvn_tx_complete = ndn_nrf_ble_unicast_hvn_tx_complete;
  observer.on_mtu_rqst = ndn_nrf_ble_unicast_on_mtu_rqst;
  observer.on_recvd_data = ndn_nrf_ble_recvd_data_unicast;
  observer.on_adv_stopped = ndn_nrf_ble_legacy_adv_stopped;
  nrf_sdk_ble_ndn_lite_ble_unicast_transport_add_observer(observer);

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

int ndn_nrf_ble_send_extended_adv_packet(const char *fail_msg) {
  if (nrf_sdk_ble_adv_start(current_packet_block_to_send, current_packet_block_to_send_size,
          ndn_nrf_ble_face_adv_uuid, true, NDN_NRF_BLE_ADV_NUM,
          ndn_nrf_ble_adv_stopped) != NRF_BLE_OP_SUCCESS) {
    printf(fail_msg);
    // always set this pointer to NULL if sending extended advertisement packet fails, so that
    // the face doesn't get stuck into thinking its still sending something
    current_packet_block_to_send_p == NULL;
    return -1;
  }
  return 1;
}

int ndn_nrf_ble_send_unicast_packet(const char *fail_msg) {
  if (nrf_sdk_ble_ndn_lite_ble_unicast_transport_send(current_packet_block_to_send_p,
       current_packet_block_to_send_size) != NRF_BLE_OP_SUCCESS) {
    printf(fail_msg);
    return -1;
  }
  return 1;
}

// below are callback functions for BLE related events

void ndn_nrf_ble_legacy_adv_stopped() {
  printf("ndn_nrf_ble_legacy_adv_stopped got called.\n");
}

void ndn_nrf_ble_unicast_on_mtu_rqst(uint16_t conn_handle) {
  printf("ndn_nrf_ble_unicast_on_mtu_rqst got called.\n");
}

void ndn_nrf_ble_unicast_connected(uint16_t conn_handle) {
  printf("ndn_nrf_ble_unicast_connected got called.\n");
}

void ndn_nrf_ble_unicast_hvn_tx_complete(uint16_t conn_handle) {
  printf("ndn_nrf_ble_unicast_hvn_tx_complete got called.\n");

  // if current_packet_block_to_send_p isn't NULL, then that means that this notification transmission complete
  // event was due to a call to ndn_nrf_ble_face_send, rather than the sign on basic client
  if (current_packet_block_to_send_p != NULL) {
    printf("in ndn_nrf_ble_unicast_hvn_tx_complete, current_packet_block_to_send_p wasn't NULL.\n");
    if (nrf_sdk_ble_ndn_lite_ble_unicast_transport_disconnect(ndn_nrf_ble_unicast_disconnected) == NRF_BLE_OP_FAILURE) {
      printf("nrf_sdk_ble_adv_start is being called within ndn_nrf_ble_unicast_hvn_tx_complete\n");
      ndn_nrf_ble_send_extended_adv_packet("nrf_sdk_ble_adv_start inside of ndn_nrf_ble_adv_stopped "
                                           "failed.\n");
    } else {
      // if ndn_lite_ble_unicast_transport_disconnect returned NRF_BLE_OP_SUCCESS, it means that we will have
      // to wait for the on disconnect callback
      printf("in ndn_nrf_ble_unicast_hvn_tx_complete, ndn_lite_ble_unicast_transport_disconnect "
             "returned NRF_BLE_OP_SUCCESS\n");
    }
  } else {
    printf("in ndn_nrf_ble_unicast_hvn_tx_complete, "
           "current_packet_block_to_send_p was NULL.\n");
  }
}

void ndn_nrf_ble_unicast_disconnected() {
  printf("ndn_nrf_ble_unicast_disconnected got called.\n");

  // now that we are disconnected from the unicast connection with the controller, we can
  // actually send the data; after we finish sending, we will reconnect to the controller and
  // also restart scanning for packets from the other board, so that we can simultaneously detect
  // other ndn-lite ble face messages as well as messages from the unicast connection to the phone
  if (current_packet_block_to_send_p != NULL) {
    printf("in ndn_nrf_ble_unicast_disconnected, current_packet_block_to_send_p wasn't NULL.\n");
    ndn_nrf_ble_send_extended_adv_packet("nrf_sdk_ble_adv_start inside of "
                                         "ndn_nrf_ble_unicast_disconnected failed.\n");
  } else {
    printf("in ndn_nrf_ble_unicast_disconnected, current_packet_block_to_send_p was NULL.\n");
    // because the current_packet_block_to_send_p was NULL, it means that the disconnection wasn't
    // triggered by the ndn-lite ble face to send data, and may be due to the controller moving out of
    // range; in that case, we resume legacy advertisements,
    // in order to connect to the controller as soon as it can be connected to again
    nrf_sdk_ble_ndn_lite_ble_unicast_transport_adv_start();
  }
}

void ndn_nrf_ble_adv_stopped(void) {
  printf("ndn_nrf_ble_adv_stopped got called.\n");

  // make sure to set current_packet_block_to_send_p to NULL to indicate that we have sent
  // this packet to both the controller through unicast and through extended advertising broadcast
  current_packet_block_to_send_p = NULL;

  // this is a hack for now; since we are using ble advertising for both the ndn-lite ble face
  // and the secure sign on ble object, we will just share advertising between them; any time that
  // the ndn-lite ble face is not advertising in order to send out multicast packets, the secure
  // sign-on client will be using legacy advertising to find potential controllers
  nrf_sdk_ble_ndn_lite_ble_unicast_transport_adv_start();
}

void ndn_nrf_ble_recvd_data_ext_adv(const uint8_t *p_data, uint8_t length) {
  printf("RX frame  (ext adv), payload len %u: \n", (unsigned)length);

  ndn_face_receive(&nrf_ble_face.intf, p_data + NDN_NRF_BLE_ADV_PAYLOAD_HEADER_LENGTH,
      length - NDN_NRF_BLE_ADV_PAYLOAD_HEADER_LENGTH);
}

void ndn_nrf_ble_recvd_data_unicast(const uint8_t *p_data, uint16_t length) {
  printf("RX frame (unicast), payload len %u: \n", (unsigned)length);

  ndn_face_receive(&nrf_ble_face.intf, p_data,
      (uint8_t)length);
}