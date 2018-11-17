/*
 * Copyright (C) Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-nrf52840.h"
#include <encode/data.h>
#include <stdio.h>

static ndn_nrf52840_802154_face_t nrf52840_802154_face;

ndn_nrf52840_802154_face_t*
ndn_nrf52840_init_802154_get_face_instance()
{
  return &nrf52840_802154_face;
}

/************************************************************/
/*  Adaptation Helper Functions                             */
/************************************************************/

void
ndn_nrf52840_init_802154_packet(uint8_t* message)
{
  memset(message, 0, NDN_NRF52840_802154_MAX_MESSAGE_SIZE);

  // frame header:
  message[0] = 0x41; // FCF, valued 0x9841
  message[1] = 0x98; // == 1001.1000.0100.0001
  //                    \\\_Data frame
  //                  .\_Security off
  //                 \_No more frames
  //                \_no ACK wanted
  //               \_PAN ID compressed
  //             .\_reserved
  //           \\_reserved
  //        .\\_DST address is short
  //      \\_IEEE802.15.4 frame
  //    \\_SRC address is short
  //
  message[2] = 0xff; // sequence number -- filled in later
  message[3] = nrf52840_802154_face.pan_id[0]; // PAN ID
  message[4] = nrf52840_802154_face.pan_id[1];
  message[5] = nrf52840_802154_face.short_address[0]; // short DST addr
  message[6] = nrf52840_802154_face.short_address[1];
  message[7] = 0; // short SRC addr
  message[8] = 0;
  // end of header
}

/************************************************************/
/*  Inherit Face Interfaces                                 */
/************************************************************/

int
ndn_nrf52840_802154_face_up(struct ndn_face_intf* self)
{
  nrf52840_802154_face.on_error(2);
  self->state = NDN_FACE_STATE_UP;
  nrf_802154_receive();
  return 0;
}

int
ndn_nrf52840_802154_face_send(struct ndn_face_intf* self, const ndn_name_t* name,
                              const uint8_t* packet, uint32_t size)
{
  nrf52840_802154_face.on_error(3);
  (void)self;
  (void)name;
  uint8_t packet_block[NDN_NRF52840_802154_MAX_MESSAGE_SIZE];
  int packet_block_size = 0;

  // init header
  ndn_nrf52840_init_802154_packet(packet_block);
  packet_block[2] = nrf52840_802154_face.packet_id&0xff;

  // init payload
  if (size <= NDN_NRF52840_802154_MAX_PAYLOAD_SIZE) {
    memcpy(&packet_block[9], packet, NDN_NRF52840_802154_MAX_MESSAGE_SIZE - 9);
  }
  else {
    // TBD
  }

  // send out the packet
  if (nrf_802154_transmit(packet_block, packet_block_size, true)) {
    int delay_loops = 0;
    nrf52840_802154_face.on_error(2);
    while (!nrf52840_802154_face.tx_done
           && !nrf52840_802154_face.tx_failed && (delay_loops < 4)) {
      for(uint32_t i = 0; i < 0x500000; ++i)
        __asm__ __volatile__("nop":::);
      ++delay_loops;
    }
    if (nrf52840_802154_face.tx_done) {
      printf("TX finished.\r\n");
      nrf52840_802154_face.packet_id++;
      nrf52840_802154_face.on_error(3);
      return 0;
    }
    else if (nrf52840_802154_face.tx_failed) {
      printf("TX failed due to busy: %u\r\n",
             (unsigned)nrf52840_802154_face.tx_errorcode);
      return -1;
    }
    else {
      printf("TX TIMEOUT!\r\n");
      nrf52840_802154_face.on_error(4);
      return -2;
    }
  }
  return -3;
}


int
ndn_nrf52840_802154_face_down(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DOWN;
  return 0;
}

void
ndn_nrf52840_802154_face_destroy(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DESTROYED;
  return;
}

ndn_nrf52840_802154_face_t*
ndn_nrf52840_802154_face_construct(uint16_t face_id,
                                   const uint8_t* extended_address, const uint8_t* pan_id,
                                   const uint8_t* short_address, bool promisc,
                                   ndn_on_error_callback_t error_callback)
{
  printf("\r\ninit 802.15.4 driver\r\n");
  nrf_802154_init();
  nrf_802154_short_address_set(short_address);
  nrf_802154_extended_address_set(extended_address);
  nrf_802154_pan_id_set(pan_id);
  if(promisc)
    nrf_802154_promiscuous_set(true);
  nrf_802154_tx_power_set(-20);
  nrf_802154_channel_set(NDN_NRF52840_802154_CHANNEL);
#if NRF_802154_ACK_TIMEOUT_ENABLED
  nrf_802154_ack_timeout_set(100);
#endif // NRF_802154_ACK_TIMEOUT_ENABLED

  nrf52840_802154_face.intf.up = ndn_nrf52840_802154_face_up;
  nrf52840_802154_face.intf.send = ndn_nrf52840_802154_face_send;
  nrf52840_802154_face.intf.down = ndn_nrf52840_802154_face_down;
  nrf52840_802154_face.intf.destroy = ndn_nrf52840_802154_face_destroy;
  nrf52840_802154_face.intf.face_id = face_id;
  nrf52840_802154_face.intf.state = NDN_FACE_STATE_DESTROYED;
  nrf52840_802154_face.intf.type = NDN_FACE_TYPE_NET;

  nrf52840_802154_face.tx_done = false;
  nrf52840_802154_face.tx_failed = false;
  nrf52840_802154_face.tx_errorcode = 0;
  nrf52840_802154_face.pan_id[0] = *pan_id;
  nrf52840_802154_face.pan_id[1] = *(pan_id + 1);
  nrf52840_802154_face.short_address[0] = *short_address;
  nrf52840_802154_face.short_address[1] = *(short_address + 1);
  nrf52840_802154_face.packet_id = 0;
  nrf52840_802154_face.on_error = error_callback;

  nrf52840_802154_face.on_error(1);
  return &nrf52840_802154_face;
}

//================================================================
void
nrf_802154_transmitted(const uint8_t * p_frame, uint8_t * p_ack,
                       uint8_t length, int8_t power, uint8_t lqi)
{
  (void)p_frame;
  (void)length;
  (void)power;
  (void)lqi;

  nrf52840_802154_face.on_error(1);
  nrf52840_802154_face.tx_done = true;

  if (p_ack != NULL) {
    nrf_802154_buffer_free(p_ack);
  }
}

void
nrf_802154_transmit_failed(const uint8_t * p_frame, nrf_802154_tx_error_t error)
{
  (void) p_frame;

  nrf52840_802154_face.tx_failed = true;
  nrf52840_802154_face.tx_errorcode = error;
}

void
nrf_802154_received(uint8_t* p_data, uint8_t length, int8_t power, uint8_t lqi)
{
  printf("RX frame, power %d, lqi %u, payload len %u: ",
         (int) power, (unsigned) lqi, (unsigned) length);

  ndn_face_receive(&nrf52840_802154_face.intf, &p_data[9], length - 9);

  nrf_802154_buffer_free(p_data);
}
