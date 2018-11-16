/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "pit.h"
#include "error-code.h"

int
pit_entry_add_incoming_face(ndn_pit_entry_t* entry, ndn_face_intf_t* face)
{
  for (uint8_t i = 0; i < entry->incoming_face_size; i ++) {
    if (entry->incoming_face[i] == face) {
      return 0;
    }
  }
  if (entry->incoming_face_size == 3) {
    return NDN_FWD_ERROR_PIT_ENTRY_FACE_LIST_FULL;
  }
  entry->incoming_face[entry->incoming_face_size] = face;
  entry->incoming_face_size ++;
  return 0;
}
