/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "face-table.h"

void ndn_facetab_init(void* memory, ndn_table_id_t capacity){
  ndn_table_id_t i;
  ndn_face_table_t* self = (ndn_face_table_t*)memory;
  self->capacity = capacity;
  for(i = 0; i < capacity; i ++){
    self->slots[i] = NULL;
  }
}

ndn_table_id_t ndn_facetab_register(ndn_face_table_t* self, ndn_face_intf_t* face){
  ndn_table_id_t i;
  for(i = 0; i < self->capacity; i ++){
    if(self->slots[i] == NULL){
      self->slots[i] = face;
      return i;
    }
  }
  return NDN_INVALID_ID;
}

void ndn_facetab_unregister(ndn_face_table_t* self, ndn_table_id_t id){
  self->slots[id] = NULL;
}
