/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "direct-face.h"
#include "error-code.h"

int
ndn_direct_face_up(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_UP;
  return 0;
}

void
ndn_direct_face_destroy(struct ndn_face_intf* self)
{
  ndn_direct_face_t* direct_face;
  direct_face = container_of(self, ndn_direct_face_t, intf);
  for (int i = 0; i < NDN_DIRECT_FACE_CB_ENTRY_SIZE; i++) {
    direct_face->cb_entries[i].interest_name.components_size = NDN_FWD_INVALID_NAME_SIZE;
  }
  self->intf.state = NDN_FACE_STATE_DESTORYED;
  return;
}

int
ndn_direct_face_down(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DOWN;
  return 0;
}

int
ndn_direct_face_send(struct ndn_face_intf* self, const ndn_name_t* name,
                     const uint8_t* packet, uint32_t size)
{
  ndn_decoder_t decoder;
  uint32_t probe = 0;
  uint8_t isInterest = 0;
  uint8_t bypass = (name == NULL)?0:1;

  decoder_init(&decoder, packet, size);
  decoder_get_type(&decoder, &probe);
  if (probe == TLV_Interest) {
    isInterest = 1;
  }
  else if (probe == TLV_Data) {
    // do nothing
  }
  else {
    // There should not be fragmentation in direct face
    return 1;
  }
  if (bypass == 0) {
    // this function is supposed to be called by the forwarder,
    // which has already finished name decoding
    // bypass should be 1
    return 1;
  }

  ndn_direct_face_t* direct_face;
  direct_face = container_of(self, ndn_direct_face_t, intf);
  for (int i = 0; i < NDN_DIRECT_FACE_CB_ENTRY_SIZE; i++) {
    if (direct_face->cb_entries[i].is_prefix == isInterest && isInterest == 0
        && ndn_name_compare(direct_face->cb_entries[i].interest_name, name) == 0) {
      direct_face->cb_entries[i].on_data(packet, size);
      return 0;
    }
    if (direct_face->cb_entries[i].is_prefix == isInterest && isInterest == 1
        && ndn_name_is_prefix(direct_face->cb_entries[i].interest_name, name) == 0) {
      direct_face->cb_entries[i].on_interest(packet, size);
      return 0;
    }
  }
  return NDN_FWD_NO_MATCHED_CALLBACK;
}

void
ndn_direct_face_construct(ndn_direct_face_t* self, uint16_t face_id)
{
  self->intf.up = ndn_direct_face_up;
  self->intf.send = ndn_direct_face_send;
  self->intf.down = ndn_direct_face_down;
  self->intf.destroy = ndn_direct_face_destroy;
  self->intf.face_id = face_id;
  self->intf.state = NDN_FACE_STATE_DESTORYED;
  self->intf.type = NDN_FACE_TYPE_APP;
}

int
ndn_direct_face_express_interest(ndn_direct_face_t* self, const ndn_name_t* interest_name,
                                 uint8_t* interest, uint32_t interest_size,
                                 ndn_on_data_callback on_data, ndn_interest_timeout_callback on_interest_timeout)
{
  for (int i = 0; i < NDN_DIRECT_FACE_CB_ENTRY_SIZE; i++) {
    if (self->cb_entries[i].interest_name.components_size == NDN_FWD_INVALID_NAME_SIZE) {
      self->cb_entries[i].interest_name = interest_name;
      self->cb_entries[i].is_prefix = 0;
      self->cb_entries[i].on_data = on_data;
      self->cb_entries[i].on_timeout = on_interest_timeout;
      self->cb_entries[i].on_interest = NULL;
      ndn_face_receive(self->intf, interest, interest_size);
      return 0;
    }
  }
  return NDN_FWD_APP_FACE_CB_TABLE_FULL;
}

int
ndn_direct_face_register_prefix(ndn_direct_face_t* self, const ndn_name_t* prefix_name,
                                ndn_on_interest_callback on_interest)
{
  for (int i = 0; i < NDN_DIRECT_FACE_CB_ENTRY_SIZE; i++) {
    if (self->cb_entries[i].interest_name.components_size == NDN_FWD_INVALID_NAME_SIZE) {
      self->cb_entries[i].interest_name = prefix_name;
      self->cb_entries[i].is_prefix = 1;
      self->cb_entries[i].on_data = NULL;
      self->cb_entries[i].on_timeout = NULL;
      self->cb_entries[i].on_interest = on_interest;
      return 0;
    }
  }
  return NDN_FWD_APP_FACE_CB_TABLE_FULL;
}
