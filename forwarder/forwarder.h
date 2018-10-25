/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FOWARDER_H_
#define FORWARDER_FOWARDER_H_

#include "pit.h"
#include "fib.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_forwarder {
  ndn_fib_t fib;
  ndn_pit_t pit;
  ndn_face_table_t face_table;

} ndn_forwarder_t;

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FOWARDER_H_
