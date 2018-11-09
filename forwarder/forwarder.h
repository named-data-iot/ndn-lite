/*
 * Copyright (C) 2018 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FOWARDER_H_
#define FORWARDER_FOWARDER_H_

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
forwarder_get_instance(void);

// Recv data packet
// data [optional] Decoded data packet, used by bypass
int
forwarder_on_incoming_data(ndn_forwarder_t* self, ndn_face_t* face, ndn_data_t *data,
                           const uint8_t *raw_data, uint32_t size);

// Recv interest packet
// interest [optional] Decoded interest packet, used by bypass
int
forwarder_on_incoming_interest(ndn_forwarder_t* self, ndn_face_t* face, ndn_interest_t *interest,
                               const uint8_t *raw_interest, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FOWARDER_H_
