/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "dummy-face.h"
#include "../encode/data.h"
#include <stdio.h>
#include <stdlib.h>

/************************************************************/
/*  Inherit Face Interfaces                                 */
/************************************************************/

int
ndn_dummy_face_up(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_UP;
  printf("Dummy Face [%u] Up\n", self->face_id);
  return NDN_SUCCESS;
}

int
ndn_dummy_face_send(struct ndn_face_intf* self,
                    const uint8_t* packet, uint32_t size)
{
  uint32_t i = 0;

  if(self->state != NDN_FACE_STATE_UP){
    printf("Dummy face [%u] unable to send the packet.\n", self->face_id);
    return NDN_FWD_FACE_DOWN;
  }
  printf("Dummy Face [%u] send packet:", self->face_id);
  for(i = 0; i < size; i++){
    printf(" %02X", packet[i]);
  }
  printf("\n");

  return NDN_SUCCESS;
}

int
ndn_dummy_face_down(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DOWN;
  printf("Dummy Face [%u] Down\n", self->face_id);
  return NDN_SUCCESS;
}

void
ndn_dummy_face_destroy(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DESTROYED;
  printf("Dummy Face [%u] Destroyed\n", self->face_id);

  ndn_forwarder_unregister_face(self);
  free(container_of(self, ndn_dummy_face_t, intf));
}

ndn_dummy_face_t*
ndn_dummy_face_construct()
{
  ndn_dummy_face_t* face;

  face = malloc(sizeof(ndn_dummy_face_t));
  if(face == NULL)
    return NULL;

  face->intf.up = ndn_dummy_face_up;
  face->intf.send = ndn_dummy_face_send;
  face->intf.down = ndn_dummy_face_down;
  face->intf.destroy = ndn_dummy_face_destroy;
  face->intf.face_id = NDN_INVALID_ID;
  face->intf.state = NDN_FACE_STATE_UP;
  face->intf.type = NDN_FACE_TYPE_NET;

  if(ndn_forwarder_register_face(&face->intf) != NDN_SUCCESS){
    free(face);
    return NULL;
  }

  printf("Dummy Face [%u] Constructed\n", face->intf.face_id);

  return face;
}
