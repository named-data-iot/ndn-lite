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

/**
 * Forwarding Information Base (FIB) class.
 */
typedef struct ndn_fib{
  ndn_nametree_t* nametree;
  uint16_t capacity;
  ndn_fib_entry_t slots[];
}ndn_fib_t;

void ndn_face_unregister_from_fib(ndn_fib_t* fib, ndn_face_intf_t* face)
{
  for (uint16_t i = 0; i < fib -> capacity; ++i) {
    for (int j = 0; j < )
  }
}