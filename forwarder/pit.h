/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_PIT_H_
#define FORWARDER_PIT_H_

#include "../encoding/interest.h"

typedef int (*ndn_on_data_callback_t)(uint8_t* interest, uint32_t interest_size,
                                      uint8_t* data, uint32_t interest_size);

typedef int (*ndn_interest_timeout_callback_t)(uint8_t* interest, uint32_t interest_size);


typedef struct ndn_pit_entry {
  ndn_name_t interest_name;

  ndn_face_t[3] incoming_face;
  uint8_t incoming_face_size;
  ndn_face_t[3] outgoing_face;
  uint8_t outgoing_face_size;

  uint32_t timestamp;

  ndn_on_data_callback_t on_data;
  ndn_interest_timeout_callback_t on_timeout;
} ndn_pit_entry_t;

typedef ndn_pit_entry_t[NDN_PIT_MAX_SIZE] ndn_pit_t;


#endif FORWARDER_PIT_H
