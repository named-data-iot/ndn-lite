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

ndn_face_unregister_from_fib()