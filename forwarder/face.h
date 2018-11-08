/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FACE_H_
#define FORWARDER_FACE_H_

#include "../encode/ndn_constants.h"
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ndn_face;
typedef int(*ndn_iface_send_func)(struct ndn_face* self, const uint8_t* packet, uint32_t size);
typedef int(*ndn_iface_close_func)(struct ndn_face* self);
typedef void(*ndn_iface_destructor)(struct ndn_face* self);
typedef struct ndn_iface{
  size_t size;
  ndn_iface_send_func send;
  ndn_iface_close_func close;
  ndn_iface_destructor destroy;
} ndn_iface_t;

typedef struct ndn_face {
  const ndn_iface_t* klass;  // sign of derived class
  void* extension;    // Derived class members (we don't have malloc!)

  uint16_t face_id;
  uint8_t state;
  uint8_t type;

  uint8_t local_uri[10];
  uint8_t remote_uri[10];
} ndn_face_t;

typedef ndn_face_t ndn_face_table_t[NDN_FACE_TABLE_MAX_SIZE];

static inline int
ndn_face_send(ndn_face_t* self, const uint8_t* packet, uint32_t size)
{
  return self->klass->send(self, packet, size);
}

static inline int
ndn_face_close(ndn_face_t* self)
{
  return self->klass->close(self);
}

static inline void
ndn_face_destroy(ndn_face_t* self)
{
  self->klass->destroy(self);
}

// The function calls the on_data callbacks and on_interest callbacks
// supposed to be invoked by the adaptation layer functions
int
ndn_face_receive(ndn_face_t* self, const uint8_t* packet, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_FACE_H_
