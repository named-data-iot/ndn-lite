/*
 * Copyright (C) 2018 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
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

/**
 * The structure to present NDN-Lite forwarder.
 * We will support content support in future versions.
 * The NDN forwarder is a singleton in an application.
 */
typedef struct ndn_forwarder {
  /**
   * The forwarding information base (FIB).
   */
  ndn_fib_t fib;
  /**
   * The pending Interest table (PIT).
   */
  ndn_pit_t pit;
} ndn_forwarder_t;

/**
 * Get a running instance of forwarder.
 * @return the pointer to the forwarder instance.
 */
ndn_forwarder_t*
ndn_forwarder_get_instance(void);

/**
 * Init the NDN-Lite forwarder.
 * This function should be invoked before any face registration and packet sending.
 * @return the pointer to the forwarder instance.
 */
ndn_forwarder_t*
ndn_forwarder_init(void);

/**
 * Add FIB entry into the FIB.
 * This function should be invoked before sending a packet through the specific face.
 * @param name_prefix. Input. The FIB's name prefix.
 * @param face. Input/Output. The face instance to send the packet out.
 * @param cost. The cost of sending a packet through the @param face. When more than one faces
 *        can be used to send a packet, the face with lower cost will be used.
 * @return 0 if there is no error.
 */
 int
 ndn_forwarder_fib_insert(const ndn_name_t* name_prefix,
                          ndn_face_intf_t* face, uint8_t cost);

/**
 * Let the forwarder receive a Data packet.
 * This function is supposed to be invoked by face implementation ONLY.
 * @param self. Input/Output. The forwarder to receive the Data packet.
 * @param face. Input. The face instance who transmits the packet to the forwarder.
 * @param raw_data. Input. The wire format Data received by the @param face.
 * @param size. Input. The size of the wire format Data.
 * @return 0 if there is no error.
 */
int
ndn_forwarder_on_incoming_data(ndn_forwarder_t* self, ndn_face_intf_t* face,
                               const uint8_t *raw_data, uint32_t size);

/**
 * Let the forwarder receive a Interest packet.
 * This function is supposed to be invoked by face implementation ONLY.
 * @param self. Input/Output. The forwarder to receive the Interest packet.
 * @param face. Input. The face instance who transmits the packet to the forwarder.
 * @param raw_data. Input. The wire format Interest received by the @param face.
 * @param size. Input. The size of the wire format Interest.
 * @return 0 if there is no error.
 */
int
ndn_forwarder_on_incoming_interest(ndn_forwarder_t* self, ndn_face_intf_t* face,
                                   const uint8_t *raw_interest, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FOWARDER_H
