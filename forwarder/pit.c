/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
 
#include "pit.h"

ndn_pit_entry_t*
pit_next_match(const ndn_pit_t* pit, ndn_name_t* name, ndn_pit_entry_t* iterator)
{
  for(iterator ++; iterator < &(*pit)[NDN_PIT_MAX_SIZE]; iterator ++) {
    // TODO: prefix match?
    if(ndn_name_compare(&iterator->interest_name, name) == 0){
      return iterator;
    }
  }
  return NULL;
}

int
pit_init(ndn_pit_t* pit)
{
  ndn_pit_entry_t* it;
  
  for(it = &(*pit)[0]; it < &(*pit)[NDN_PIT_MAX_SIZE]; it ++) {
    it->interest_name.components_size = NDN_FWD_INVALID_NAME_SIZE;
  }
  
  return 0;
}

ndn_pit_entry_t*
pit_find_or_insert(ndn_pit_t* pit, ndn_name_t* name)
{
  ndn_pit_entry_t* it;
  
  // Find
  for(it = &(*pit)[0]; it < &(*pit)[NDN_PIT_MAX_SIZE]; it ++) {
    if(ndn_name_compare(&it->interest_name, name) == 0) {
      return it;
    }
  }
  
  // Insert
  for(it = &(*pit)[0]; it < &(*pit)[NDN_PIT_MAX_SIZE]; it ++) {
    if(it->interest_name.components_size == NDN_FWD_INVALID_NAME_SIZE) {
      it->interest_name = *name;
      it->incoming_face_size = 0;
      return it;
    }
  }
  
  return NULL;
}

bool
pit_add_incoming_face(ndn_pit_entry_t* entry, ndn_face_t* face)
{
  int i;
  
  for(i = 0; i < entry->incoming_face_size; i ++) {
    if(entry->incoming_face[i] == face) {
      return true;
    }
  }

  if(entry->incoming_face_size == 3) {
    return false;
  }
  entry->incoming_face[entry->incoming_face_size] = face;
  entry->incoming_face_size ++;
  return true;
}
