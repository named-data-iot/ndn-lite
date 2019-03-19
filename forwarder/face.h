/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FACE_H_
#define FORWARDER_FACE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "../ndn-enums.h"

/*
#define container_of(ptr, type, member) ({                \
  const typeof(((type *)0)->member) *__mptr = (ptr);      \
  (type *)((char *)__mptr - offsetof(type, member)); })
*/

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup NDNFwdFace Face
 * @ingroup NDNFwd
 * @{
 */

struct ndn_face_intf;

/**
 * The interface up function.
 * Turn on the specified interface.
 * @param self Input. The interface to trun on.
 * @return 0 if there is no error.
 */
typedef int (*ndn_face_intf_up)(struct ndn_face_intf* self);

/**
 * The packet sending function.
 * Send out a packet, Interest, Data, etc.
 * @param self Input. The interface through which the packet will be sent.
 * @param name [optional]Input. The name of the packet.
 * @param packet Input. The wire format packet buffer.
 * @param size Input. The size of the wire format packet buffer.
 * @return 0 if there is no error.
 */
<<<<<<< HEAD
typedef int (*ndn_face_intf_send)(struct ndn_face_intf* self,
                                  const uint8_t* packet, uint32_t size);
=======
typedef int (*ndn_face_intf_send)(struct ndn_face_intf* self, const uint8_t* packet, uint32_t size);
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee

/**
 * The interface down function.
 * Shutdown the specified interface temporarily
 * @param self Input. The interface to turn off.
 * @return 0 if there is no error.
 */
typedef int (*ndn_face_intf_down)(struct ndn_face_intf* self);

/**
 * The interface destructor.
 * Destroy the specified interface permanently.
 * @param self Input. The interface to destroy.
 */
typedef void (*ndn_face_intf_destroy)(struct ndn_face_intf* self);

/**
 * Abstract NDN network face.
 * An abstract base class for all faces.
 * Derived classes should implement the function ndn_face_intf#up, ndn_face_intf#send,
 * ndn_face_intf#down, and ndn_face_intf#destroy with platform-specific APIs via assigning
 * function pointers in @c ndn_face_intf.
 * @attention @c ndn_face_intf should always be the first member of any face class.
 */
typedef struct ndn_face_intf {
  ndn_face_intf_up up;
  ndn_face_intf_send send;
  ndn_face_intf_down down;
  ndn_face_intf_destroy destroy;

  /**
   * Unique Face ID.
   */
  uint16_t face_id;
  /**
   * The state of the face: NDN_FACE_STATE_DOWN, NDN_FACE_STATE_UP, NDN_FACE_STATE_DESTROYED.
   */
  uint8_t state;
  /**
   * The type of the face: NDN_FACE_TYPE_APP, NDN_FACE_TYPE_NET, NDN_FACE_TYPE_UNDEFINED
   */
  uint8_t type;
} ndn_face_intf_t;

/**
 * Turn on the interface.
 * This function is supposed to be invoked by the forwarder ONLY.
 * @param self Input. The interface to turn on.
 * @return 0 if there is no error.
 */
static inline int
ndn_face_up(ndn_face_intf_t* self)
{
  if (self->state != NDN_FACE_STATE_UP)
    return self->up(self);
  return 0;
}

/**
 * Send a packet through the interface to the network.
 * This function is supposed to be invoked by the forwarder ONLY.
 * @param self Input. The interface through which the packet will be sent.
 * @param name [optional]Input. The name of the packet.
 * @param packet Input. The wire format packet buffer.
 * @param size Input. The size of the wire format packet buffer.
 * @return 0 if there is no error.
 */
static inline int
ndn_face_send(ndn_face_intf_t* self, const uint8_t* packet, uint32_t size)
{
  if (self->state != NDN_FACE_STATE_UP)
    self->up(self);
  return self->send(self, packet, size);
}

/**
 * Turn down the interface.
 * @param self Input. The interface to turn off.
 * @return 0 if there is no error.
 */
static inline int
ndn_face_down(ndn_face_intf_t* self)
{
  self->state = NDN_FACE_STATE_DOWN;
  return self->down(self);
}

/**
 * Destroy the interface.
 * @param self Input. The interface to destroy.
 */
static inline void
ndn_face_destroy(ndn_face_intf_t* self)
{
  self->state = NDN_FACE_STATE_DESTROYED;
  self->destroy(self);
}

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_FACE_H_
