/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_PIT_H_
#define FORWARDER_PIT_H_

#include "../encode/interest.h"
#include "face.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*ndn_on_data_callback_t)(uint8_t* data, uint32_t data_size);

typedef int (*ndn_interest_timeout_callback_t)(uint8_t* interest, uint32_t interest_size);


typedef struct ndn_pit_entry {
  // components_size < 0 indicates an empty entry
  ndn_name_t interest_name;

  // Add when necessary

  ndn_face_t* incoming_face[3];
  uint8_t incoming_face_size;
  // ndn_face_t[3] outgoing_face;
  // uint8_t outgoing_face_size;

  //uint32_t timestamp; //TODO: How to time-out?

  //ndn_on_data_callback_t on_data;
  //ndn_interest_timeout_callback_t on_timeout;
} ndn_pit_entry_t;

typedef ndn_pit_entry_t ndn_pit_t[NDN_PIT_MAX_SIZE];

// Wish to decouple PIT and forwarder, so create functions below

int
pit_init(ndn_pit_t* pit);

ndn_pit_entry_t*
pit_next_match(const ndn_pit_t* pit, ndn_name_t* name, ndn_pit_entry_t* iterator);

ndn_pit_entry_t*
pit_find_or_insert(ndn_pit_t* pit, ndn_name_t* name);

static inline ndn_pit_entry_t*
pit_first_match(const ndn_pit_t* pit, ndn_name_t* name)
{
  return pit_next_match(pit, name, &(*pit)[-1]);
}

// This function should return the one that can be used for next-match
// e.g. prior one if a linked list is used
static inline ndn_pit_entry_t*
pit_delete(ndn_pit_t* pit, ndn_pit_entry_t* iterator)
{
  iterator->interest_name.components_size = -1;
  return iterator;
}

bool
pit_add_incoming_face(ndn_pit_entry_t* entry, ndn_face_t* face);

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_PIT_H
