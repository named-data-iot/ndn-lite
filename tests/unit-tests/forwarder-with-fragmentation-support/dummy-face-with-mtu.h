/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

/***********************************************************
 **  This Face Implementation is only for tests
 **  MTU is to test fragmentation support
 **  Local loop only
 ************************************************************/

#ifndef NDN_DUMMY_FACE_H
#define NDN_DUMMY_FACE_H

#include "ndn-lite/forwarder/forwarder.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MTU 64
#define MAX_PACKETS_IN_BUFFER 8

typedef struct {
  uint8_t* block_value;
  uint32_t size;
} packet_t;


/**
 * The structure to represent a dummy face. This structure should only be declared for tests.
 */
typedef struct ndn_dummy_face_with_mtu {
  /**
   * The inherited interface abstraction.
   */
  ndn_face_intf_t intf;
  uint32_t mtu;
} ndn_dummy_face_with_mtu_t;

/**
 * Construct the dummy face and initialize its state.
 * @return the pointer to the constructed dummy face.
 */
ndn_dummy_face_with_mtu_t *
ndn_dummy_face_construct();

/*
 * Call Forwarder.receive() on assembled data in buffer
 */
void recv_from_face(ndn_dummy_face_with_mtu_t *self);

/*
 * Send oversized packet in fragments
 */
int ndn_dummy_face_send_with_fragmenter(struct ndn_face_intf *self,
                                        const uint8_t *packet, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // NDN_DUMMY_FACE_H
