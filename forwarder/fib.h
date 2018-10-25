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

typedef struct ndn_fib_entry {
  ndn_name_t name_prefix;
  ndn_face_t next_hop;
  uint8_t cost;
} ndn_fib_entry_t;

typedef ndn_fib_entry_t[NDN_FIB_MAX_SIZE] ndn_fib_t;

#endif FORWARDER_PIT_H
