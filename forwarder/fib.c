/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "fib.h"
#include "error_code.h"

ndn_fib_entry_t*
fib_lookup(ndn_fib_t* self, const ndn_name_t* name)
{
  ndn_fib_entry_t* it;
  
  for(it = &(*self)[0]; it < &(*self)[NDN_FIB_MAX_SIZE]; it ++) {
    if(ndn_name_is_prefix_of(&it->name_prefix, name)){
      return it;
    }
  }
  return NULL;
}

ndn_fib_entry_t*
fib_lookup_by_face(ndn_fib_t* self, const ndn_face_t* face)
{
  ndn_fib_entry_t* it;
  
  for(it = &(*self)[0]; it < &(*self)[NDN_FIB_MAX_SIZE]; it ++) {
    if(it->name_prefix.components_size != NDN_FWD_INVALID_NAME_SIZE &&
       it->next_hop == face) {
      return it;
    }
  }
  return NULL;
}

int
fib_init(ndn_fib_t* self)
{
  ndn_fib_entry_t* it;
  
  for(it = &(*self)[0]; it < &(*self)[NDN_FIB_MAX_SIZE]; it ++) {
    it->name_prefix.components_size = NDN_FWD_INVALID_NAME_SIZE;
  }
  
  return 0;
}

bool
fib_insert(ndn_fib_t* self, ndn_name_t* name_prefix, ndn_face_t* face, uint8_t cost)
{
  ndn_fib_entry_t* it;
  
  for(it = &(*self)[0]; it < &(*self)[NDN_FIB_MAX_SIZE]; it ++) {
    if(ndn_name_compare(&it->name_prefix, name_prefix) == 0) {
      return false;
    }
  }
  
  for(it = &(*self)[0]; it < &(*self)[NDN_FIB_MAX_SIZE]; it ++) {
    if(it->name_prefix.components_size == NDN_FWD_INVALID_NAME_SIZE) {
      it->name_prefix = *name_prefix;
      it->next_hop = face;
      it->cost = cost;
      return true;
    }
  }
  
  return false;
}
