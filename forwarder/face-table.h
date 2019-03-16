/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FACE_TABLE_H_
#define FORWARDER_FACE_TABLE_H_

#include "face.h"
#include "../ndn-constants.h"

typedef struct ndn_face_table{
  uint16_t capacity;
  ndn_face_intf_t* slots[];
}ndn_face_table_t;

#define NDN_FACE_TABLE_RESERVE_SIZE(entry_count) \
  (sizeof(ndn_face_table_t) + sizeof(ndn_face_intf_t*) * (entry_count))

void ndn_facetab_init(void* memory, uint16_t capacity);

uint16_t ndn_facetab_register(ndn_face_table_t* self, ndn_face_intf_t* face);

// ATTENTION: This should be called with ndn_fib_unregister && ndn_pit_unregister
void ndn_facetab_unregister(ndn_face_table_t* self, uint16_t id);

#endif // FORWARDER_FACE_TABLE_H_
