/*
 * Copyright (C) Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-nrf-802154-face.h"
#include "../encode/data.h"
#include "../encode/fragmentation-support.h"
#include <stdio.h>

static ndn_nrf_802154_face_t nrf_802154_face;
static frag_buffer[NDN_FRAG_BUFFER_MAX];
static ndn_frag_assembler_t assembler;

ndn_nrf_802154_face_t*
ndn_nrf_802154_face_get_instance()
{
  return &nrf_802154_face;
}

/************************************************************/
/*  Adaptation Helper Functions                             */
/************************************************************/

static void
ndn_nrf_init_802154_packet(uint8_t* message)
{
  memset(message, 0, NDN_NRF_802154_MAX_MESSAGE_SIZE);

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
  message[3] = nrf_802154_face.pan_id[0]; // PAN ID
  message[4] = nrf_802154_face.pan_id[1];
  message[5] = nrf_802154_face.short_address[0]; // short DST addr
  message[6] = nrf_802154_face.short_address[1];
  message[7] = 0; // short SRC addr
  message[8] = 0;
  // end of header
}

static void
ndn_nrf_init_802154_radio(const uint8_t* extended_address, const uint8_t* pan_id,
                          const uint8_t* short_address, bool promisc)
{
  printf("\r\ninit 802.15.4 driver\r\n");

  nrf_802154_init();
  nrf_802154_short_address_set(short_address);
  nrf_802154_extended_address_set(extended_address);
  nrf_802154_pan_id_set(pan_id);
  if(promisc)
    nrf_802154_promiscuous_set(true);
  nrf_802154_tx_power_set(-20);
  nrf_802154_channel_set(NDN_NRF_802154_CHANNEL);
  nrf_802154_receive();

  printf("TX power currently set to %ddBm\r\n", (int)nrf_802154_tx_power_get());
}

/************************************************************/
/*  Inherit Face Interfaces                                 */
/************************************************************/

int
ndn_nrf_802154_face_up(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_UP;
  return 0;
}

int
ndn_nrf_802154_face_send(struct ndn_face_intf* self, const ndn_name_t* name,
                         const uint8_t* packet, uint32_t size)
{
  (void)self;
  (void)name;
  uint8_t packet_block[NDN_NRF_802154_MAX_MESSAGE_SIZE];

  // init header
  ndn_nrf_init_802154_packet(packet_block);
  packet_block[2] = nrf_802154_face.packet_id & 0xff;

  // init payload
  if (size <= NDN_NRF_802154_MAX_PAYLOAD_SIZE) {
    memcpy(&packet_block[9], packet, size);
    _nrf_802154_transmission(packet_block, size + 9, true);
  }
  else {
    // fragmentation
    ndn_fragmenter_t fragmenter;
    uint16_t id = 99; // only for test, should be random
    ndn_fragmenter_init(&fragmenter, packet, size, NDN_NRF_802154_MAX_PAYLOAD_SIZE, 
                        id);
    printf("%d pieces needed\n", fragmenter.total_frag_num);
    while (fragmenter.counter < fragmenter.total_frag_num) {
      ndn_fragmenter_fragment(&fragmenter, &packet_block[9]); 
      printf("fragmentation output ONE piece, No. %d\n", fragmenter.counter);
      _nrf_802154_transmission(packet_block, size + 9, true);
    }
  }
  return 0;
}

static int
_nrf_802154_transmission(uint8_t* packet_block, uint32_t packet_size, bool flag)
{
  if (nrf_802154_transmit(packet_block, packet_size, flag)) {
    nrf_802154_face.tx_done = false;
    nrf_802154_face.tx_failed = false;
    int delay_loops = 0;
    while (!nrf_802154_face.tx_done
           && !nrf_802154_face.tx_failed && (delay_loops < 8)) {
      for(uint32_t i = 0; i < 0x500000; ++i)
        __asm__ __volatile__("nop":::);
      ++delay_loops;
    }
    if (nrf_802154_face.tx_done) {
      printf("TX finished.\r\n");
      nrf_802154_face.packet_id++;
      nrf_802154_face.on_error(3);
      return 0;
    }
    else if (nrf_802154_face.tx_failed) {
      printf("TX failed due to busy: %u\r\n",
             (unsigned)nrf_802154_face.tx_errorcode);
      nrf_802154_face.on_error(4);
      return -1;
    }
    else {
      printf("TX TIMEOUT!\r\n");
      nrf_802154_face.on_error(1);
      return -2;
    }
  }
  return -3;
}

int
ndn_nrf_802154_face_down(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DOWN;
  return 0;
}

void
ndn_nrf_802154_face_destroy(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DESTROYED;
  return;
}

ndn_nrf_802154_face_t*
ndn_nrf_802154_face_construct(uint16_t face_id,
                              const uint8_t* extended_address, const uint8_t* pan_id,
                              const uint8_t* short_address, bool promisc,
                              ndn_on_error_callback_t error_callback)
{
  nrf_802154_face.intf.up = ndn_nrf_802154_face_up;
  nrf_802154_face.intf.send = ndn_nrf_802154_face_send;
  nrf_802154_face.intf.down = ndn_nrf_802154_face_down;
  nrf_802154_face.intf.destroy = ndn_nrf_802154_face_destroy;
  nrf_802154_face.intf.face_id = face_id;
  nrf_802154_face.intf.state = NDN_FACE_STATE_DESTROYED;
  nrf_802154_face.intf.type = NDN_FACE_TYPE_NET;

  nrf_802154_face.tx_done = false;
  nrf_802154_face.tx_failed = false;
  nrf_802154_face.tx_errorcode = 0;
  nrf_802154_face.pan_id[0] = *pan_id;
  nrf_802154_face.pan_id[1] = *(pan_id + 1);
  nrf_802154_face.short_address[0] = *short_address;
  nrf_802154_face.short_address[1] = *(short_address + 1);
  nrf_802154_face.packet_id = 0;
  nrf_802154_face.on_error = error_callback;

  ndn_nrf_init_802154_radio(extended_address, pan_id, short_address, promisc);

  nrf_802154_face.on_error(1);

  ndn_frag_assembler_init(&assembler, frag_buffer, sizeof(frag_buffer));

  return &nrf_802154_face;
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

  nrf_802154_face.tx_done = true;

  if (p_ack != NULL) {
    nrf_802154_buffer_free(p_ack);
  }
}

void
nrf_802154_transmit_failed(const uint8_t * p_frame, nrf_802154_tx_error_t error)
{
  (void) p_frame;

  nrf_802154_face.tx_failed = true;
  nrf_802154_face.tx_errorcode = error;
}

void
nrf_802154_received(uint8_t* p_data, uint8_t length, int8_t power, uint8_t lqi)
{
  nrf_802154_face.on_error(2);
  printf("RX frame, power %d, lqi %u, payload len %u: ",
         (int) power, (unsigned) lqi, (unsigned) length);

  if (length - 9 <= NDN_NRF_802154_MAX_PAYLOAD_SIZE) {
    ndn_frag_assembler_assemble_frag(&assembler, &p_data[9], length);
    if (assembler.is_finished) {
      ndn_face_receive(&nrf_802154_face.intf, frag_buffer, assembler.offset);
      ndn_frag_assembler_init(&assembler, frag_buffer, sizeof(frag_buffer));
    }  
  }
  else {
  }
  nrf_802154_buffer_free(p_data);
}
