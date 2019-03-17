/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "fib.h"

void ndn_fib_init(void* memory, uint16_t capacity, ndn_nametree_t* nametree){
  uint16_t i;
  ndn_fib_t* self = (ndn_fib_t*)memory;
  self->capacity = capacity;
  self->nametree = nametree;
  for(i = 0; i < capacity; i ++){
    self->slots[i].nametree_id = NDN_INVALID_ID;
  }
}

typedef struct ndn_fib_entry {
  ndn_bitset_t nexthop;
  ndn_on_interest_func on_interest;
  void* userdata;
  uint16_t nametree_id;
} ndn_fib_entry_t;

void set_fib_entry(ndn_fib_entry_t *entry,
                  ndn_bitset_t nexthop,
                  ndn_on_interest_func on_interest,
                  void* userdata,
                  uint16_t nametree_id)
{
  entry -> nexthop = nexthop;
  entry -> userdata = userdata;
  entry -> on_interest = on_interest;
  entry -> nametree_id = nametree_id;
}

void refresh_fib_entry(ndn_fib_entry_t *entry)
{
  set_fib_entry(entry, 0, NULL, NULL, NDN_INVALID_ID);
}

int ndn_fib_add_new_entry(ndn_fib_t* fib , int offset)
{
  for (uint16_t i = 0; i < fib -> capacity; ++i)
    if (fib -> slots[i].nametree_id == NDN_INVALID_ID) {
      refresh_fib_entry(fib -> slots[i]);
      fib -> slots[i].nametree_id = offset;
      return i;
    }
  return NDN_INVALID_ID;
}

void ndn_face_unregister_from_fib(ndn_fib_t* fib, ndn_face_intf_t* face)
{
  for (uint16_t i = 0; i < fib -> capacity; ++i)
    bitset_unset(fib -> slots[i].nexthop , face -> face_id);
}

ndn_fib_entry_t*
ndn_get_fib_entry(ndn_fib_t* fib, ndn_nametree_t* nametree, uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_find_or_insert(nametree, prefix, length);
  if (entry == NULL) return NULL;
  if (entry -> fib_id == NDN_INVALID_ID) {
    entry -> fib_id = ndn_fib_add_new_entry(fib , entry - nametree);
    if (entry -> fib_id == NDN_INVALID_ID) return NULL;
  }
  return fib -> slots[entry -> fib_id];
}