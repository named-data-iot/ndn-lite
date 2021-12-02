/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */
#define ENABLE_NDN_LOG_INFO 0
#define ENABLE_NDN_LOG_DEBUG 0
#define ENABLE_NDN_LOG_ERROR 1
#include "cs.h"
#include "../encode/data.h"
#include "../util/msg-queue.h"
#include "../util/logger.h"

static inline void
ndn_cs_entry_reset(ndn_cs_entry_t* self){
  self->nametree_id = NDN_INVALID_ID;
  self->last_time = 0;
  self->express_time = 0;
  self->on_data = NULL;
  self->userdata = NULL;
  self->content = NULL;
  self->content_len = 0;
  self->fresh_until = 0;
  // Don't reset options.nonce here
}

void
ndn_cs_init(void* memory, ndn_table_id_t capacity, ndn_nametree_t* nametree){
  ndn_table_id_t i;
  ndn_cs_t* self = (ndn_cs_t*)memory;
  self->capacity = capacity;
  self->nametree = nametree;
  for(i = 0; i < capacity; i++){
    ndn_cs_entry_reset(&self->slots[i]);
    self->slots[i].options.nonce = 0;
  }
}

void
ndn_cs_remove_entry(ndn_cs_t* self, ndn_cs_entry_t* entry){
  ndn_nametree_at(self->nametree, entry->nametree_id)->cs_id = NDN_INVALID_ID;
  ndn_cs_entry_reset(entry);
}

static ndn_table_id_t
ndn_cs_add_new_entry(ndn_cs_t* cs , int nametree_id){
  ndn_table_id_t i;
  for (i = 0; i < cs->capacity; ++i) {
    if (cs->slots[i].nametree_id == NDN_INVALID_ID) {
      ndn_cs_entry_reset(&cs->slots[i]);
      cs->slots[i].nametree_id = nametree_id;
      return i;
    }
  }
  return NDN_INVALID_ID;
}

ndn_cs_entry_t*
ndn_cs_find_or_insert(ndn_cs_t* self, uint8_t* name, size_t length){
  nametree_entry_t* entry = ndn_nametree_find_or_insert(self->nametree, name, length);
  if(entry == NULL){
    return NULL;
  }
  if(entry->cs_id == NDN_INVALID_ID){
    entry->cs_id = ndn_cs_add_new_entry(self, ndn_nametree_getid(self->nametree, entry));
    NDN_LOG_DEBUG("[CS] Add a new CS entry\n");
    if(entry->cs_id == NDN_INVALID_ID){
      return NULL;
    }
  }
  return &self->slots[entry->cs_id];
}

ndn_cs_entry_t*
ndn_cs_find(ndn_cs_t* self, uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_find(self->nametree, prefix, length);
  if (entry == NULL || entry->cs_id == NDN_INVALID_ID) {
    return NULL;
  }
  return &self->slots[entry->cs_id];
}

ndn_cs_entry_t*
ndn_cs_prefix_match(ndn_cs_t* self, uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_prefix_match(self->nametree, prefix, length, NDN_NAMETREE_CS_TYPE);
  if (entry == NULL || entry->cs_id == NDN_INVALID_ID) {
    return NULL;
  }
  return &self->slots[entry->cs_id];
}

void
ndn_insert_cs_entry_with_content(ndn_cs_entry_t* cs_entry, uint8_t* data, size_t length){
  ndn_data_t ndn_data_content;

  // decode the data to extract the freshnessPeriod of the data
  uint32_t be_signed_start, be_signed_end;
  ndn_data_tlv_decode_no_verify(&ndn_data_content, data, length, &be_signed_start, &be_signed_end);

  // create new CS entry with content
  free(cs_entry->content);
  cs_entry->content = NULL;
  cs_entry->content = malloc(length);
  memcpy(cs_entry->content, data, length);
  cs_entry->content_len = length;

  // set the timestamps and freshnessPeriod for the cs_entry
  ndn_time_ms_t now = ndn_time_now_ms();
  cs_entry->last_time = now;
  cs_entry->fresh_until = ndn_data_content.metainfo.freshness_period + now;
  return;
}
