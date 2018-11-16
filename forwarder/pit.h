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

typedef struct ndn_pit_entry {
  // components_size < 0 indicates an empty entry
  ndn_name_t interest_name;

  // Add when necessary
  ndn_face_intf_t* incoming_face[3];
  uint8_t incoming_face_size;

  //uint32_t timestamp; //TODO: How to time-out?
} ndn_pit_entry_t;

typedef ndn_pit_entry_t ndn_pit_t[NDN_PIT_MAX_SIZE];

int
pit_entry_add_incoming_face(ndn_pit_entry_t* entry, ndn_face_intf_t* face);

static inline void
pit_entry_delete(ndn_pit_entry_t* entry)
{
  entry->interest_name.components_size = NDN_FWD_INVALID_NAME_SIZE;
}

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_PIT_H
