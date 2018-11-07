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

typedef struct send_interest_event {
  uint8_t* interest_block;
  uint32_t block_size;
  ndn_on_data_callback_t on_data;
  ndn_interest_timeout_callback_t on_timeout;
} send_interest_event_t;

typedef struct ndn_nrf52840_context {
  bool tx_done;
  bool tx_failed;
  nrf_802154_tx_error_t tx_errorcode;

  uint8_t pan_id[2];
  uint8_t short_address[2];

  uint16_t packet_id;

  send_interest_event_t send_interest_events[5];
  uint8_t events_size;
} ndn_nrf52840_context_t;

void
ndn_nrf52840_init_802154_radio(const uint8_t* extended_address, const uint8_t* pan_id,
                               const uint8_t* short_address, bool promisc);
void
ndn_nrf52840_init_802154_packet(uint8_t* message, const uint8_t* pan_id,
                                const uint8_t* short_address);

// void
// ndn_nrf52840_802154_register_prefix();

void
ndn_nrf52840_802154_express_interest(ndn_interest_t* interest,
                                     ndn_on_data_callback_t on_data,
                                     ndn_interest_timeout_callback_t on_timeout);


#endif // NDN_ADAPTATION_NDN_NRF52840_H
