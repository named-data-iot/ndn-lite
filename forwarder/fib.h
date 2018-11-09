/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FIB_H_
#define FORWARDER_FIB_H_

#include "../encode/interest.h"
#include "error_code.h"
#include "face.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*ndn_on_interest_callback_t)(uint8_t* interest, uint32_t interest_size);

typedef struct ndn_fib_entry {
  ndn_name_t name_prefix;
  ndn_face_t *next_hop;
  uint8_t cost;

  //ndn_on_interest_callback_t on_interest;
} ndn_fib_entry_t;

typedef ndn_fib_entry_t ndn_fib_t[NDN_FIB_MAX_SIZE];

ndn_fib_entry_t*
fib_lookup(ndn_fib_t* self, const ndn_name_t* name);

ndn_fib_entry_t*
fib_lookup_by_face(ndn_fib_t* self, const ndn_face_t* face);

int
fib_init(ndn_fib_t* self);

bool
fib_insert(ndn_fib_t* self, ndn_name_t* name_prefix, ndn_face_t* face, uint8_t cost);

static inline void
fib_delete(ndn_fib_t* self, ndn_fib_entry_t* entry)
{
  entry->name_prefix.components_size = NDN_FWD_INVALID_NAME_SIZE;
}

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FIB_H
