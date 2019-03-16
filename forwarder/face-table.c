/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "face-table.h"

void ndn_facetab_init(void* memory, uint16_t capacity){
  uint16_t i;
  ndn_face_table_t* self = (ndn_face_table_t*)memory;
  self->capacity = capacity;
  for(i = 0; i < capacity; i ++){
    self->slots[i] = NULL;
  }
}

uint16_t ndn_facetab_register(ndn_face_table_t* self, ndn_face_intf_t* face){
  uint16_t i;
  for(i = 0; i < self->capacity; i ++){
    if(self->slots[i] == NULL){
      self->slots[i] = face;
      return i;
    }
  }
  return NDN_INVALID_ID;
}

// ATTENTION: This should be called with ndn_fib_unregister && ndn_pit_unregister
void ndn_facetab_unregister(ndn_face_table_t* self, uint16_t id){
  self->slots[id] = NULL;
}
