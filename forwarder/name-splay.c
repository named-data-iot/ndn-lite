/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "name-splay.h"
#include <stdbool.h>
#include <string.h>
#include "../encode/forwarder-helper.h"

#define LEFT  0
#define RIGHT 1

static void
nametree_reset_entry(ndn_nametree_t *self,
                      nametree_entry_t* entry,
                      nametree_entry_t* next_unused)
{
  entry->sub = self->nil;
  entry->cop[LEFT] = self->nil;
  entry->cop[RIGHT] = next_unused;
  entry->fib_id = NDN_INVALID_ID;
  entry->pit_id = NDN_INVALID_ID;
}

void
ndn_nametree_init(void* memory, ndn_table_id_t capacity){
  int i;
  ndn_nametree_t *self = (ndn_nametree_t*)memory;

  self->nil = &self->pool[0];
  self->root = &self->pool[1];

  // NIL node. Its LEFT and RIGHT point to a temporary tree each.
  nametree_reset_entry(self, self->nil, self->nil);

  // "/" node. Its RIGHT points to a unused linked-list.
  nametree_reset_entry(self, self->root, &self->pool[2]);

  for (i = 2; i < capacity; ++i) {
    nametree_reset_entry(self, &self->pool[i], &self->pool[i + 1]);
  }
  self->pool[capacity - 1].cop[RIGHT] = self->nil;
}

static void
nametree_zig(ndn_nametree_t* self, nametree_entry_t* par, int dir){
  // par->sub is the root for current level, self->nil is the temp tree.
  nametree_entry_t *new_root = par->sub->cop[dir];
  par->sub->cop[dir] = self->nil->cop[dir];
  self->nil->cop[dir] = par->sub;
  par->sub = new_root;
}

static void
nametree_zigzig(ndn_nametree_t* self, nametree_entry_t* par, int dir){
  // par->sub is the root for current level, self->nil is the temp tree.
  nametree_entry_t *middle = par->sub->cop[dir];
  nametree_entry_t *new_root = middle->cop[dir];
  middle->cop[dir] = self->nil->cop[dir];
  self->nil->cop[dir] = middle;
  par->sub->cop[dir] = middle->cop[1^dir];
  middle->cop[1^dir] = par->sub;
  par->sub = new_root;
}

static void
nametree_finish(ndn_nametree_t* self, nametree_entry_t* par, int dir){
  // The front node of the reversed temporary tree
  nametree_entry_t *head = self->nil->cop[dir];
  // The new child of head after putting head back
  nametree_entry_t *child = par->sub->cop[!dir];
  nametree_entry_t *next_head;
  while (head != self->nil) {
    next_head = head->cop[dir];
    head->cop[dir] = child;
    child = head;
    self->nil->cop[dir] = next_head;
    head = next_head;
  }
  par->sub->cop[!dir] = child;
}

static int
nametree_splay(ndn_nametree_t* self, nametree_entry_t* par, uint8_t name[], size_t len) {
  int dir1, dir2, ret;
  while(true) {
    ret = memcmp(name, par->sub->val, len);
    dir1 = ret > 0;
    if (ret == 0 || par->sub->cop[dir1] == self->nil)
      break;
    ret = memcmp(name, par->sub->cop[dir1]->val, len);
    dir2 = ret > 0;
    if (ret == 0 || par->sub->cop[dir1]->cop[dir2] == self->nil) {
      nametree_zig(self, par, dir1);
      break;
    }
    if (dir1 != dir2) {
      nametree_zig(self, par, dir1);
      nametree_zig(self, par, dir2);
    } else {
      nametree_zigzig(self, par, dir1);
    }
  }
  nametree_finish(self, par, LEFT);
  nametree_finish(self, par, RIGHT);
  return ret;
}

static nametree_entry_t*
nametree_newnode(ndn_nametree_t* self,
                  uint8_t name[],
                  size_t len)
{
  nametree_entry_t* ret = self->root->cop[RIGHT];
  if(ret == self->nil){
    return NULL;
  }
  self->root->cop[RIGHT] = ret->cop[RIGHT];

  ret->sub = self->nil;
  ret->fib_id = NDN_INVALID_ID;
  ret->pit_id = NDN_INVALID_ID;
  memcpy(ret->val, name, len);

  return ret;
}

static nametree_entry_t*
nametree_find_or_insert_sub(ndn_nametree_t* self,
                             nametree_entry_t* par,
                             uint8_t name[],
                             size_t len)
{
  nametree_entry_t *oldroot, *newroot;
  int dir, compare_ret;

  compare_ret = nametree_splay(self, par, name, len);
  oldroot = par->sub;
  if(compare_ret == 0){
    return oldroot;
  }else{
    newroot = nametree_newnode(self, name, len);
    if(newroot == NULL){
      return NULL;
    }
    dir = compare_ret < 0 ? LEFT : RIGHT;
    newroot->cop[dir] = oldroot->cop[dir];
    newroot->cop[1 ^ dir] = oldroot;
    oldroot->cop[dir] = self->nil;
    par->sub = newroot;
    return newroot;
  }
}

nametree_entry_t*
ndn_nametree_find_or_insert(ndn_nametree_t *self, uint8_t name[], size_t len){
  uint32_t type, varlen, complen;
  uint8_t* ptr;
  nametree_entry_t* par;
  nametree_entry_t* cur;

  ptr = tlv_get_type_length(name, len, &type, &varlen);
  par = self->root;
  while(ptr < name + len){
    complen = tlv_get_type_length(ptr, name + len - ptr, &type, &varlen) - ptr;
    complen += varlen;
    cur = nametree_find_or_insert_sub(self, par, ptr, complen);
    if(cur == NULL){
      return NULL;
    }
    par = cur;
    ptr += complen;
  }
  return par;
}

nametree_entry_t*
ndn_nametree_find(ndn_nametree_t *self, uint8_t name[], size_t len){
  uint32_t type, varlen, complen;
  uint8_t* ptr;
  nametree_entry_t* par;
  nametree_entry_t* cur;
  int compare_ret;

  ptr = tlv_get_type_length(name, len, &type, &varlen);
  par = self->root;
  while(ptr < name + len){
    complen = tlv_get_type_length(ptr, name + len - ptr, &type, &varlen) - ptr;
    complen += varlen;
    compare_ret = nametree_splay(self, par, ptr, complen);
    cur = par->sub;
    if(cur == self->nil || compare_ret != 0){
      return NULL;
    }
    par = cur;
    ptr += complen;
  }
  return par;
}

nametree_entry_t*
ndn_nametree_prefix_match(
  ndn_nametree_t *self,
  uint8_t name[],
  size_t len,
  enum NDN_NAMETREE_ENTRY_TYPE entry_type)
{
  uint32_t type, varlen, complen;
  uint8_t* ptr;
  nametree_entry_t* par;
  nametree_entry_t* cur;
  nametree_entry_t* last = NULL;
  int compare_ret;

  ptr = tlv_get_type_length(name, len, &type, &varlen);
  par = self->root;

  if(entry_type == NDN_NAMETREE_FIB_TYPE && par->fib_id != NDN_INVALID_ID){
    last = par;
  }
  if(entry_type == NDN_NAMETREE_PIT_TYPE && par->pit_id != NDN_INVALID_ID){
    last = par;
  }

  while(ptr < name + len){
    complen = tlv_get_type_length(ptr, name + len - ptr, &type, &varlen) - ptr;
    complen += varlen;
    compare_ret = nametree_splay(self, par, ptr, complen);
    cur = par->sub;
    if(cur == self->nil || compare_ret != 0){
      return last;
    }
    par = cur;
    ptr += complen;

    if(entry_type == NDN_NAMETREE_FIB_TYPE && par->fib_id != NDN_INVALID_ID){
      last = par;
    }
    if(entry_type == NDN_NAMETREE_PIT_TYPE && par->pit_id != NDN_INVALID_ID){
      last = par;
    }
  }
  return last;
}

nametree_entry_t*
ndn_nametree_at(ndn_nametree_t *self, ndn_table_id_t id){
  return &self->pool[id];
}

ndn_table_id_t
ndn_nametree_getid(ndn_nametree_t *self, nametree_entry_t* entry){
  return entry - self->pool;
}

// TODO: Delete, clean
