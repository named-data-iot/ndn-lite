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

#define container_of(ptr, type, member) ({                      \
      const typeof( ((type *)0)->member ) *__mptr = (ptr);      \
      (type *)( (char *)__mptr - offsetof(type,member) );})

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Face is an abstraction for NDN forwarder face
 *
 * This is a abstract 'class'. The adaptation layer should realize concrete
 * face
 */

struct ndn_face_intf;
typedef int (*ndn_face_intf_up)(struct ndn_face_intf* self);
typedef int (*ndn_face_intf_send)(struct ndn_face_intf* self, const ndn_name_t* name, const uint8_t* packet, uint32_t size);
typedef int (*ndn_face_intf_down)(struct ndn_face_intf* self);
typedef void (*ndn_face_intf_destroy)(struct ndn_face_intf* self);

// Abstract methods. Should be implemented by adaptation layer
typedef struct ndn_face_intf {
  ndn_face_intf_up up;
  ndn_face_intf_send send;
  ndn_face_intf_down down;
  ndn_face_intf_destroy destroy;

  uint16_t face_id;
  uint8_t state;
  uint8_t type;
} ndn_face_intf_t;

// supposed to be invoked by forwarder ONLY
static inline int
ndn_face_up(ndn_face_intf_t* self)
{
  if (self->state != NDN_FACE_STATE_UP)
    return self->up(self);
  return 0;
}

// send Interest from Forwarder
static inline int
ndn_face_send(ndn_face_intf_t* self, const ndn_name_t* name, const uint8_t* packet, uint32_t size)
{
  if (self->state == NDN_FACE_STATE_DOWN)
    self->up(self);
  return self->send(self, name, packet, size);
}

static inline int
ndn_face_down(ndn_face_intf_t* self)
{
  self->state = NDN_FACE_STATE_DOWN;
  return self->down(self);
}

static inline void
ndn_face_destroy(ndn_face_intf_t* self)
{
  self->state = NDN_FACE_STATE_DESTROYED;
  self->destroy(self);
}

// send Interest to Forwarder (Forwarder receives)
// supposed to be invoked by face itself ONLY
int
ndn_face_receive(ndn_face_intf_t* self, const uint8_t* packet, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_FACE_H_
