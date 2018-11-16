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
#include "face.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_fib_entry {
  ndn_name_t name_prefix;
  ndn_face_intf_t* next_hop;
  uint8_t cost;
} ndn_fib_entry_t;

typedef ndn_fib_entry_t ndn_fib_t[NDN_FIB_MAX_SIZE];

static inline void
fib_entry_delete(ndn_fib_entry_t* entry)
{
  entry->name_prefix.components_size = NDN_FWD_INVALID_NAME_SIZE;
}

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FIB_H
