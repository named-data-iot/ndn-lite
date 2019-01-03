/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FACE_H_
#define FORWARDER_FACE_H_

#include "../encode/name.h"

#define container_of(ptr, type, member) ({                \
  const typeof(((type *)0)->member) *__mptr = (ptr);      \
  (type *)((char *)__mptr - offsetof(type, member)); })

#ifdef __cplusplus
extern "C" {
#endif

struct ndn_face_intf;

/**
 * ndn_face_intf_up is a function pointer to the interface up function.
 * After invoking the function, the interface will be turned on.
 * @param self. Input. The interface to trun on.
 * @return 0 if there is no error.
 */
typedef int (*ndn_face_intf_up)(struct ndn_face_intf* self);

/**
 * ndn_face_intf_send is a function pointer to the interface packet sending function.
 * After invoking the function, the interface will send out the packet.
 * @param self. Input. The interface through which the packet will be sent.
 * @param name. [optional]Input. The name of the packet.
 * @param packet. Input. The wire format packet buffer.
 * @param size. Input. The size of the wire format packet buffer.
 * @return 0 if there is no error.
 */
typedef int (*ndn_face_intf_send)(struct ndn_face_intf* self,
                                  const ndn_name_t* name, const uint8_t* packet, uint32_t size);

/**
 * ndn_face_intf_down is a function pointer to the interface down function.
 * After invoking the function, the interface will temporally be shut down.
 * @param self. Input. The interface to turn off.
 * @return 0 if there is no error.
 */
typedef int (*ndn_face_intf_down)(struct ndn_face_intf* self);

/**
 * ndn_face_intf_destroy is a function pointer to the interface destroy function.
 * After invoking the function, the interface will permanently be destroyed.
 * @param self. Input. The interface to destroy.
 */
typedef void (*ndn_face_intf_destroy)(struct ndn_face_intf* self);

/**
 * ndn_face_intf is an abstraction for NDN network face.
 * This is an abstract 'class'.
 * A concrete face should realize the function up, send, down, and destroy with
 * platform-specific APIs and bind the functions to the function pointers in
 * ndn_face_intf.
 * ndn_face_intf should be the first struct attribute of a concrete face structure.
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
   * The state of the face: NDN_FACE_STATE_DOWN, NDN_FACE_STATE_UP, NDN_FACE_STATE_DESTROYED
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
 * @param self. Input. The interface to turn on.
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
 * @param self. Input. The interface through which the packet will be sent.
 * @param name. [optional]Input. The name of the packet.
 * @param packet. Input. The wire format packet buffer.
 * @param size. Input. The size of the wire format packet buffer.
 * @return 0 if there is no error.
 */
static inline int
ndn_face_send(ndn_face_intf_t* self, const ndn_name_t* name, const uint8_t* packet, uint32_t size)
{
  if (self->state != NDN_FACE_STATE_UP)
    self->up(self);
  return self->send(self, name, packet, size);
}

/**
 * Turn down the interface.
 * @param self. Input. The interface to turn off.
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
 * @param self. Input. The interface to destroy.
 */
static inline void
ndn_face_destroy(ndn_face_intf_t* self)
{
  self->state = NDN_FACE_STATE_DESTROYED;
  self->destroy(self);
}

/**
 * Send Interest to the Forwarder (Forwarder receives)
 * @param self. Input. The interface to transmit the packet to the forwarder.
 * @param packet. Input. The wire format packet buffer.
 * @param size. Input. The size of the wire format packet buffer.
 * @return 0 if there is no error.
 */
int
ndn_face_receive(ndn_face_intf_t* self, const uint8_t* packet, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_FACE_H_
