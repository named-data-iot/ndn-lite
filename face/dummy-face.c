/*
 * Copyright (C) Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "dummy-face.h"
#include "../encode/data.h"
#include <stdio.h>

/************************************************************/
/*  Inherit Face Interfaces                                 */
/************************************************************/

int
ndn_dummy_face_up(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_UP;
  printf("Dummy Face UP\n");
  return 0;
}

int
ndn_dummy_face_send(struct ndn_face_intf* self, const uint8_t* packet, uint32_t size)
{
  (void)self;
  (void)packet;
  (void)size;
  printf("Dummy Face UP send packet\n");
  return 0;
}


int
ndn_dummy_face_down(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DOWN;
  printf("Dummy Face Down\n");
  return 0;
}

void
ndn_dummy_face_destroy(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DESTROYED;
  printf("Dummy Face Destroy\n");
  return;
}

ndn_dummy_face_t*
ndn_dummy_face_construct(ndn_dummy_face_t* face, uint16_t face_id)
{
  face->intf.up = ndn_dummy_face_up;
  face->intf.send = ndn_dummy_face_send;
  face->intf.down = ndn_dummy_face_down;
  face->intf.destroy = ndn_dummy_face_destroy;
  face->intf.face_id = face_id;
  face->intf.state = NDN_FACE_STATE_DESTROYED;
  face->intf.type = NDN_FACE_TYPE_NET;
  return face;
}
