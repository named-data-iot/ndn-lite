/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "direct-face.h"
#include "../forwarder/forwarder.h"
#include "../util/memory-pool.h"
#include "../encode/interest.h"
#include "../encode/data.h"
#include "../ndn-error-code.h"
#include "stdio.h"

static ndn_direct_face_t direct_face;
#define FACE_ENTRY_INTEREST_MAX_SIZE 100
static uint8_t face_entry_interest_pool[NDN_MEMORY_POOL_RESERVE_SIZE(FACE_ENTRY_INTEREST_MAX_SIZE, \
                                                          NDN_DIRECT_FACE_CB_ENTRY_SIZE)];

/************************************************************/
/*  Inherit Face Interfaces                                 */
/************************************************************/

int
ndn_direct_face_up(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_UP;
  return 0;
}

void
ndn_direct_face_destroy(struct ndn_face_intf* self)
{
  for (int i = 0; i < NDN_DIRECT_FACE_CB_ENTRY_SIZE; i++) {
    if (direct_face.cb_entries[i].interest_buffer.value) {
      ndn_memory_pool_free(face_entry_interest_pool,
                           direct_face.cb_entries[i].interest_buffer.value);
      direct_face.cb_entries[i].interest_buffer.value = NULL;
    }
    direct_face.cb_entries[i].interest_buffer.size = NDN_FWD_INVALID_NAME_SIZE;
  }
  self->state = NDN_FACE_STATE_DESTROYED;
  return;
}

int
ndn_direct_face_down(struct ndn_face_intf* self)
{
  self->state = NDN_FACE_STATE_DOWN;
  return 0;
}

int
ndn_direct_face_send(struct ndn_face_intf* self, const uint8_t* packet, uint32_t size)
{
  (void)self;
  ndn_decoder_t decoder;
  uint32_t probe = 0;
  uint8_t isInterest = 0;

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

  // Re-initialize and compare aganist entries
  decoder_init(&decoder, packet, size);
  for (int i = 0; i < NDN_DIRECT_FACE_CB_ENTRY_SIZE; i++) {
    ndn_decoder_t to_compare;
    decoder_init(&to_compare, direct_face.cb_entries[i].interest_buffer.value,
                 direct_face.cb_entries[i].interest_buffer.size);

    // If Data
    if (direct_face.cb_entries[i].is_prefix == isInterest && isInterest == 0) {
      int compare_result = ndn_data_interest_compare_block(&decoder, &to_compare);
      if (compare_result == 0)
        direct_face.cb_entries[i].on_data(packet, size);
      return 0;
    }

    // If Interest
    if (direct_face.cb_entries[i].is_prefix == isInterest && isInterest == 1) {
      int compare_result = ndn_interest_name_compare_block(&decoder, &to_compare);
      if (compare_result == 0 || compare_result == 2)
        direct_face.cb_entries[i].on_interest(packet, size);
      return 0;
    }

    // Re-initialize and compare aganist entries
    decoder_init(&decoder, packet, size);
  }
  return NDN_FWD_NO_MATCHED_CALLBACK;
}

ndn_direct_face_t*
ndn_direct_face_construct(uint16_t face_id)
{
  direct_face.intf.up = ndn_direct_face_up;
  direct_face.intf.send = ndn_direct_face_send;
  direct_face.intf.down = ndn_direct_face_down;
  direct_face.intf.destroy = ndn_direct_face_destroy;
  direct_face.intf.face_id = face_id;
  direct_face.intf.state = NDN_FACE_STATE_DESTROYED;
  direct_face.intf.type = NDN_FACE_TYPE_APP;

  // init memory pool and call back entries
  ndn_memory_pool_init(face_entry_interest_pool, FACE_ENTRY_INTEREST_MAX_SIZE,
                       NDN_DIRECT_FACE_CB_ENTRY_SIZE);
  for (int i = 0; i < NDN_DIRECT_FACE_CB_ENTRY_SIZE; i++) {
    direct_face.cb_entries[i].interest_buffer.value = NULL;
    direct_face.cb_entries[i].interest_buffer.size = NDN_FWD_INVALID_NAME_SIZE;
    direct_face.cb_entries[i].interest_buffer.max_size = FACE_ENTRY_INTEREST_MAX_SIZE;
  }

  return &direct_face;
}

int
ndn_direct_face_express_interest(const ndn_name_t* interest_name,
                                 uint8_t* interest, uint32_t interest_size,
                                 ndn_on_data_callback on_data, ndn_interest_timeout_callback on_interest_timeout)
{
  (void)interest_name;

  for (int i = 0; i < NDN_DIRECT_FACE_CB_ENTRY_SIZE; i++) {
    if (direct_face.cb_entries[i].interest_buffer.size == NDN_FWD_INVALID_NAME_SIZE) {
      direct_face.cb_entries[i].interest_buffer.value = ndn_memory_pool_alloc(face_entry_interest_pool);

      if (direct_face.cb_entries[i].interest_buffer.value == NULL ||
          interest_size > FACE_ENTRY_INTEREST_MAX_SIZE)
        return NDN_OVERSIZE;

      memcpy(direct_face.cb_entries[i].interest_buffer.value, interest, interest_size);
      direct_face.cb_entries[i].interest_buffer.size = interest_size;
      direct_face.cb_entries[i].is_prefix = 0;
      direct_face.cb_entries[i].on_data = on_data;
      direct_face.cb_entries[i].on_timeout = on_interest_timeout;
      direct_face.cb_entries[i].on_interest = NULL;

      // TODO: fetch lifetime from TLV encoded Interest block
      ndn_face_receive(&direct_face.intf, interest, interest_size);
      ndn_forwarder_pit_load_timeout(interest, interest_size,
                                     direct_face.cb_entries[i].on_timeout);
      return 0;
    }
  }
  return NDN_FWD_APP_FACE_CB_TABLE_FULL;
}

int
ndn_direct_face_register_prefix(const ndn_name_t* prefix_name,
                                ndn_on_interest_callback on_interest)
{
  uint32_t prefix_name_size = ndn_name_probe_block_size(prefix_name);
  uint8_t prefix_name_value[prefix_name_size];

  ndn_encoder_t prefix_encoder;
  encoder_init(&prefix_encoder, prefix_name_value, prefix_name_size);
  ndn_name_tlv_encode(&prefix_encoder, prefix_name);

  for (int i = 0; i < NDN_DIRECT_FACE_CB_ENTRY_SIZE; i++) {
    if (direct_face.cb_entries[i].interest_buffer.size == NDN_FWD_INVALID_NAME_SIZE) {
      direct_face.cb_entries[i].interest_buffer.value = ndn_memory_pool_alloc(face_entry_interest_pool);

      if (direct_face.cb_entries[i].interest_buffer.value == NULL ||
          prefix_name_size > FACE_ENTRY_INTEREST_MAX_SIZE)
        return NDN_OVERSIZE;

      memcpy(direct_face.cb_entries[i].interest_buffer.value, prefix_name_value, prefix_name_size);
      direct_face.cb_entries[i].interest_buffer.size = prefix_name_size;
      direct_face.cb_entries[i].is_prefix = 1;
      direct_face.cb_entries[i].on_data = NULL;
      direct_face.cb_entries[i].on_timeout = NULL;
      direct_face.cb_entries[i].on_interest = on_interest;

      ndn_forwarder_fib_insert(prefix_name, &direct_face.intf, NDN_FACE_DEFAULT_COST);
      return 0;
    }
  }
  return NDN_FWD_APP_FACE_CB_TABLE_FULL;
}
