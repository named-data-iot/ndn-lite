/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "fib.h"

static inline void
ndn_fib_entry_reset(ndn_fib_entry_t* self)
{
  self->nametree_id = NDN_INVALID_ID;
  self->nexthop = 0;
  self->on_interest = NULL;
  self->userdata = NULL;
}

void
ndn_fib_init(void* memory, ndn_table_id_t capacity, ndn_nametree_t* nametree)
{
  ndn_table_id_t i;
  ndn_fib_t* self = (ndn_fib_t*)memory;
  self->capacity = capacity;
  self->nametree = nametree;
  for(i = 0; i < capacity; i ++){
    ndn_fib_entry_reset(&self->slots[i]);
  }
}

static inline void
ndn_fib_remove_entry(ndn_fib_t* self, ndn_fib_entry_t* entry)
{
  ndn_nametree_at(self->nametree, entry->nametree_id)->fib_id = NDN_INVALID_ID;
  ndn_fib_entry_reset(entry);
}

void
ndn_fib_remove_entry_if_empty(ndn_fib_t* self, ndn_fib_entry_t* entry)
{
  if(entry->nametree_id == NDN_INVALID_ID){
    return;
  }
  if(entry->nexthop == 0 && entry->on_interest == NULL){
    ndn_fib_remove_entry(self, entry);
  }
}

void
ndn_fib_unregister_face(ndn_fib_t* self, ndn_table_id_t face_id)
{
  for (ndn_table_id_t i = 0; i < self -> capacity; ++i) {
    self->slots[i].nexthop = bitset_unset(self->slots[i].nexthop , face_id);
    ndn_fib_remove_entry_if_empty(self, &self->slots[i]);
  }
}

static ndn_table_id_t
ndn_fib_add_new_entry(ndn_fib_t* fib , int nametree_id)
{
  ndn_table_id_t i;
  for (i = 0; i < fib -> capacity; ++i) {
    if (fib->slots[i].nametree_id == NDN_INVALID_ID) {
      ndn_fib_entry_reset(&fib->slots[i]);
      fib->slots[i].nametree_id = nametree_id;
      return i;
    }
  }
  return NDN_INVALID_ID;
}

ndn_fib_entry_t*
ndn_fib_find_or_insert(ndn_fib_t* self, uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_find_or_insert(self->nametree, prefix, length);
  if(entry == NULL) {
    return NULL;
  }
  if(entry->fib_id == NDN_INVALID_ID) {
    entry->fib_id = ndn_fib_add_new_entry(self, ndn_nametree_getid(self->nametree, entry));
    if(entry->fib_id == NDN_INVALID_ID) {
      return NULL;
    }
  }
  return &self->slots[entry->fib_id];
}

ndn_fib_entry_t*
ndn_fib_find(ndn_fib_t* self, uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_find(self->nametree, prefix, length);
  if (entry == NULL || entry->fib_id == NDN_INVALID_ID) {
    return NULL;
  }
  return &self->slots[entry->fib_id];
}

ndn_fib_entry_t*
ndn_fib_prefix_match(ndn_fib_t* self, uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_prefix_match(self->nametree, prefix, length, NDN_NAMETREE_FIB_TYPE);
  if (entry == NULL || entry->fib_id == NDN_INVALID_ID) {
    return NULL;
  }
  return &self->slots[entry->fib_id];
}
