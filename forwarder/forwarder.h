/*
 * Copyright (C) 2018 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FOWARDER_H
#define FORWARDER_FOWARDER_H

#include "pit.h"
#include "fib.h"
#include "face.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_forwarder {
  ndn_fib_t fib;
  ndn_pit_t pit;
} ndn_forwarder_t;

// Get a running instance of current system
ndn_forwarder_t*
ndn_forwarder_get_instance(void);

ndn_forwarder_t*
ndn_forwarder_init(void);

int
ndn_forwarder_fib_insert(ndn_name_t* name_prefix,
                         ndn_face_intf_t* face, uint8_t cost);

// Recv data packet
// name [optional] Decoded data name if it's ready,
//                 then forwarder won't decode name again
// Supposed to be invoked by face ONLY
int
ndn_forwarder_on_incoming_data(ndn_forwarder_t* self, ndn_face_intf_t* face, ndn_name_t *name,
                               const uint8_t *raw_data, uint32_t size);

// Recv interest packet
// name [optional] Decoded interest name if it's ready,
//                 then forwarder won't decode name again
// Supposed to be invoked by face ONLY
int
ndn_forwarder_on_incoming_interest(ndn_forwarder_t* self, ndn_face_intf_t* face, ndn_name_t *name,
                                   const uint8_t *raw_interest, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FOWARDER_H
