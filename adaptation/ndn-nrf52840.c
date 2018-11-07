/*
 * Copyright (C) Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "nrf52840-ndn.h"
#include <forwarder/forwarder.h>

static ndn_nrf52840_context_t m_context;

void
ndn_nrf52840_init_802154_radio(const uint8_t* extended_address, const uint8_t* pan_id,
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
  nrf_802154_channel_set(NDN_NRF52840_802154_CHANNEL);
  nrf_802154_receive();

  printf("TX power currently set to %ddBm\r\n", (int)nrf_802154_tx_power_get());

  m_context.tx_done = false;
  m_context.tx_failed = false;
  m_context.pan_id[0] = *pan_id;
  m_context.pan_id[1] = *(pan_id + 1);
  m_context.short_address[0] = *short_address;
  m_context.short_address[1] = *(short_address + 1);
  m_context.packet_id = 0;
  m_context.tx_errorcode = 0;
  m_context.event_size = 0;
}

void
ndn_nrf52840_init_802154_packet(uint8_t* message)
{
  bzero(message, NDN_NRF52840_802154_MAX_MESSAGE_SIZE);

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
  message[3] = m_context.pan_id[0]; // PAN ID
  message[4] = m_context.pan_id[1];
  message[5] = m_context.short_address[0]; // short DST addr
  message[6] = m_context.short_address[1];
  message[7] = 0; // short SRC addr
  message[8] = 0;
  // end of header
}

// typedef struct send_interest_event {
//   uint8_t* interest_block;
//   uint32_t block_size;
//   ndn_on_data_callback_t on_data;
//   ndn_interest_timeout_callback_t on_timeout;
// } send_interest_event_t;
// typedef struct ndn_nrf52840_context {
//   bool tx_done;
//   bool tx_failed;
//   nrf_802154_tx_error_t tx_errorcode;

//   send_interest_event_t send_interest_events[5];
//   uint8_t events_size;
// } ndn_nrf52840_context_t;


void
ndn_nrf52840_802154_express_interest(ndn_interest_t* interest,
                                     ndn_on_data_callback_t on_data,
                                     ndn_interest_timeout_callback_t on_timeout)
{
  // create a new send event
  send_interest_event_t send_event = {
    .interest_block = interest_block,
    .block_size = block_size,
    .on_data = on_data,
    .on_timeout = on_timeout
  };
  m_context.send_interest_events[m_context.events_size] = send_event;
  m_context.events_size++;

  // init header
  uint8_t packet_block[NDN_NRF52840_802154_MAX_MESSAGE_SIZE];
  int packet_block_size = 0;
  ndn_nrf52840_init_802154_packet(packet_block);
  packet_block[2] = m_context.packet_id&0xff;

  // init payload
  uint32_t block_size = ndn_interest_probe_block_size(interest);
  if (block_size <= NDN_NRF52840_802154_MAX_PAYLOAD_SIZE) {
    encoder_t encoder;
    encoder_init(&packet_block[9], NDN_NRF52840_802154_MAX_MESSAGE_SIZE - 8);
    ndn_interest_tlv_encode(&encoder, interest);
    packet_block_size = 8 + encoder.offset;
  }
  else {
    // TBD
  }

  // send out the packet
  if (nrf_802154_transmit(message, packet_block_size, true)) {
    while(!m_context.m_tx_done && !m_context.m_tx_failed) {
      // intended loop
    }
    if (m_context.m_tx_done) {
      printf("TX finished.\r\n");
      m_context.packet_id++;
    }
    else if(m_tx_failed) {
      printf("TX failed due to busy: %u\r\n",
             (unsigned)m_context.m_tx_errorcode);
    }
    else {
      printf("TX TIMEOUT!\r\n");
    }
  }
}


//================================================================
void
nrf_802154_transmitted(const uint8_t * p_frame, uint8_t * p_ack,
                       uint8_t length, int8_t power, uint8_t lqi)
{
  (void) p_frame;
  (void) length;
  (void) power;
  (void) lqi;

  m_context.tx_done = true;

  if (p_ack != NULL) {
    nrf_802154_buffer_free(p_ack);
  }
}

void
nrf_802154_transmit_failed(const uint8_t * p_frame, nrf_802154_tx_error_t error)
{
  (void) p_frame;

  m_context.tx_failed = true;
  m_context.tx_errorcode = error;
}

void
nrf_802154_received(uint8_t * p_data, uint8_t length, int8_t power, uint8_t lqi)
{
  printf("RX frame, power %d, lqi %u, payload len %u: ",
         (int) power, (unsigned) lqi, (unsigned) length);
  for(int i = 0; i < length; ++i)
    printf("%02x ", p_data[i]);
  if(length == MAX_MESSAGE_SIZE+2)
    printf("-- temp: %5.2fC", (*(uint32_t*)&p_data[13])/4.);
  printf("\r\n");

  nrf_802154_buffer_free(p_data);
}
