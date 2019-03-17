/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "pit.h"

static inline void
ndn_pit_entry_reset(ndn_pit_entry_t* self){
  self->nametree_id = NDN_INVALID_ID;
  self->last_time = 0;
  self->express_time = 0;
  self->incoming_faces = 0;
  self->on_data = NULL;
  self->on_timeout = NULL;
  self->userdata = NULL;
}

void
ndn_pit_init(void* memory, uint16_t capacity, ndn_nametree_t* nametree){
  uint16_t i;
  ndn_pit_t* self = (ndn_pit_t*)memory;
  self->capacity = capacity;
  self->nametree = nametree;
  for(i = 0; i < capacity; i ++){
    ndn_pit_entry_reset(&self->slots[i]);
  }
}

static inline void
ndn_pit_remove_entry(ndn_pit_t* self, uint16_t index){
  (*self->nametree)[self->slots[index].nametree_id].fib_id = NDN_INVALID_ID;
  ndn_pit_entry_reset(&self->slots[index]);
}

static inline void
ndn_pit_remove_entry_if_empty(ndn_pit_t* self, uint16_t index){
  if(self->slots[index].incoming_faces == 0 &&
     self->slots[index].on_data == NULL &&
     self->slots[index].on_timeout == NULL)
  {
    ndn_pit_remove_entry(self, index);
  }
}

void
ndn_pit_unregister_face(ndn_pit_t* self, uint16_t face_id){
  for (uint16_t i = 0; i < self->capacity; ++i){
    self->slots[i].incoming_faces = bitset_unset(self->slots[i].incoming_faces, face_id);
    ndn_pit_remove_entry_if_empty(self, i);
  }
}

int
pit_entry_add_incoming_face(ndn_pit_entry_t* entry, ndn_face_intf_t* face)
{
  for (uint8_t i = 0; i < entry->incoming_face_size; i ++) {
    if (entry->incoming_face[i] == face) {
      return 0;
    }
  }
  if (entry->incoming_face_size == NDN_MAX_FACE_PER_PIT_ENTRY) {
    return NDN_FWD_PIT_ENTRY_FACE_LIST_FULL;
  }
  entry->incoming_face[entry->incoming_face_size] = face;
  entry->incoming_face_size ++;
  return 0;
}

void set_pit_entry(ndn_pit_entry_t *entry,
                  interest_options_t options,
                  uint64_t incoming_faces,
                  ndn_time_ms_t last_time,
                  ndn_time_ms_t express_time,
                  ndn_on_data_func on_data,
                  ndn_on_timeout_func on_timeout,
                  void* userdata,
                  uint16_t nametree_id)
{
  entry -> options = options;
  entry -> incoming_faces = incoming_faces;
  entry -> last_time = last_time;
  entry -> express_time = express_time;
  entry -> on_data = on_data;
  entry -> on_timeout = on_timeout;
  entry -> userdata = userdata;
  entry -> nametree_id = nametree_id;
}

void refresh_pit_entry(ndn_pit_entry_t *entry)
{
  set_pit_entry(entry, 0, 0,0,0,0,0,0, NDN_INVALID_ID);
}

int ndn_pit_add_new_entry(ndn_pit_t* pit , int offset)
{
  for (uint16_t i = 0; i < pit -> capacity; ++i)
    if (pit -> slots[i].nametree_id == NDN_INVALID_ID) {
      refresh_pit_entry(pit -> slots[i]);
      pit -> slots[i].nametree_id = offset;
      return i;
    }
  return NDN_INVALID_ID;
}

ndn_pit_entry_t*
ndn_get_fib_entry(ndn_pit_t* pit, ndn_nametree_t* nametree, uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_find_or_insert(nametree, prefix, length);
  if (entry == NULL) return NULL;
  if (entry -> pit_id == NDN_INVALID_ID) {
    entry -> pit_id = ndn_pit_add_new_entry(pit , entry - nametree);
    if (entry -> pit_id == NDN_INVALID_ID) return NULL;
  }
  return pit -> slots[entry -> pit_id];
}
