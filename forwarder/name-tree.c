/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "name-tree.h"
#include <string.h>

#define minof2(a, b) ((a) < (b) ? (a) : (b))

static void
nametree_refresh(ndn_nametree_t *nametree, int num)
{
  (*nametree)[num].left_child = NDN_INVALID_ID;
  (*nametree)[num].pit_id = NDN_INVALID_ID;
  (*nametree)[num].fib_id = NDN_INVALID_ID;

  (*nametree)[num].right_bro = (*nametree)[0].right_bro;
  (*nametree)[0].right_bro = num;
}

static int
nametree_clean(ndn_nametree_t *nametree, int num)
{
  int ret = 0;
  if (num == NDN_INVALID_ID) {
    return NDN_INVALID_ID;
  }
  else {
    (*nametree)[num].left_child = nametree_clean(nametree, (*nametree)[num].left_child);
    (*nametree)[num].right_bro = nametree_clean(nametree, (*nametree)[num].right_bro);
    if ((*nametree)[num].fib_id == NDN_INVALID_ID &&
        (*nametree)[num].pit_id == NDN_INVALID_ID &&
        (*nametree)[num].left_child == NDN_INVALID_ID) {
      ret = (*nametree)[num].right_bro;
      nametree_refresh(nametree, num);
      return ret;
    }
    else {
      return num;
    }
  }
}

static void
nametree_cleanup(ndn_nametree_t *nametree)
{
  (*nametree)[0].left_child = nametree_clean(nametree, (*nametree)[0].left_child);
}

void
ndn_nametree_init(void* memory, ndn_table_id_t capacity)
{
  ndn_nametree_t *nametree = (ndn_nametree_t*)memory;
  //all free entries are linked as right_bro of (*nametree)[0], the root of the tree.
  for (int i = 0; i < capacity; ++i) {
    (*nametree)[i].left_child = (*nametree)[i].pit_id = (*nametree)[i].fib_id = NDN_INVALID_ID;
    (*nametree)[i].right_bro = i + 1;
  }
  (*nametree)[capacity - 1].right_bro = NDN_INVALID_ID;
}

static int
nametree_create_node(ndn_nametree_t *nametree, uint8_t name[], size_t len)
{
  int output = (*nametree)[0].right_bro;
  if (output == NDN_INVALID_ID) return NDN_INVALID_ID;
  (*nametree)[0].right_bro = (*nametree)[output].right_bro;
  (*nametree)[output].left_child  = (*nametree)[output].right_bro = NDN_INVALID_ID;
  (*nametree)[output].pit_id = (*nametree)[output].fib_id = NDN_INVALID_ID;
  memcpy((*nametree)[output].val, name, len);
  return output;
}

nametree_entry_t*
ndn_nametree_find(ndn_nametree_t *nametree, uint8_t name[], size_t len)
{
  int now_node, last_node, father = 0 , offset = 0 , tmp;
  size_t component_len, eqiv_component_len;
  // TODO: Put it into decoder
  if (len < 2) return NULL;
  if (name[1] < 253) offset = 2; else offset = 4;
  while (offset < len) {
    component_len = name[offset + 1] + 2;
    eqiv_component_len = minof2(component_len, NDN_NAME_COMPONENT_BUFFER_SIZE);
    now_node = (*nametree)[father].left_child;
    last_node = NDN_INVALID_ID;
    tmp = -2;
    while (now_node != NDN_INVALID_ID) {
      tmp = memcmp(name+offset, (*nametree)[now_node].val , eqiv_component_len);
      if (tmp <= 0) break;
      last_node = now_node;
      now_node = (*nametree)[now_node].right_bro;
    }
    if (tmp != 0) {
      return NULL;
    }
    offset += component_len;
    father = now_node;
  }
  return &(*nametree)[father];
}

static nametree_entry_t*
nametree_find_or_insert_try(ndn_nametree_t *nametree, uint8_t name[], size_t len)
{
  int now_node, last_node, father = 0 , offset = 0 , tmp , new_node_number;
  size_t component_len, eqiv_component_len;
  // TODO: Put it into decoder
  if (len < 2) return NULL;
  if (name[1] < 253) offset = 2; else offset = 4;
  while (offset < len) {
    component_len = name[offset + 1] + 2;
    eqiv_component_len = minof2(component_len, NDN_NAME_COMPONENT_BUFFER_SIZE);
    now_node = (*nametree)[father].left_child;
    last_node = NDN_INVALID_ID;
    tmp = -2;
    while (now_node != NDN_INVALID_ID) {
      tmp = memcmp(name+offset, (*nametree)[now_node].val , eqiv_component_len);
      if (tmp <= 0) break;
      last_node = now_node;
      now_node = (*nametree)[now_node].right_bro;
    }
    if (tmp != 0) {
      new_node_number = nametree_create_node(nametree, name + offset , eqiv_component_len);
      if (new_node_number == NDN_INVALID_ID) return NULL;
      if(last_node == NDN_INVALID_ID){
        (*nametree)[father].left_child = new_node_number;
      }else{
        (*nametree)[last_node].right_bro = new_node_number;
      }
      (*nametree)[new_node_number].right_bro = now_node;
      now_node = new_node_number;
    }
    offset += component_len;
    father = now_node;
  }
  return &(*nametree)[father];
}

nametree_entry_t*
ndn_nametree_find_or_insert(ndn_nametree_t *nametree, uint8_t name[], size_t len)
{
  nametree_entry_t* p = nametree_find_or_insert_try(nametree, name , len);
  if (p == NULL) {
    nametree_cleanup(nametree);
    p = nametree_find_or_insert_try(nametree, name , len);
  }
  return p;
}

nametree_entry_t*
ndn_nametree_prefix_match(
                          ndn_nametree_t* nametree,
                          uint8_t name[],
                          size_t len,
                          enum NDN_NAMETREE_ENTRY_TYPE type)
{
  int now_node, last_node = NDN_INVALID_ID , father = 0 , offset = 0 , tmp;
  size_t component_len, eqiv_component_len;
  if (len < 2) return NULL;
  if (name[1] < 253) offset = 2; else offset = 4;
  while (offset < len) {
    component_len = name[offset + 1] + 2;
    eqiv_component_len = minof2(component_len, NDN_NAME_COMPONENT_BUFFER_SIZE);
    now_node = (*nametree)[father].left_child;
    tmp = -2;
    while (now_node != NDN_INVALID_ID) {
      tmp = memcmp(name+offset,(*nametree)[now_node].val , eqiv_component_len);
      if (tmp <= 0) break;
      now_node = (*nametree)[now_node].right_bro;
    }
    if (tmp == 0) {
      if ((*nametree)[now_node].fib_id != NDN_INVALID_ID && type == NDN_NAMETREE_FIB_TYPE) last_node = now_node;
      if ((*nametree)[now_node].pit_id != NDN_INVALID_ID && type == NDN_NAMETREE_PIT_TYPE) last_node = now_node;
    } else break;
    offset += component_len;
    father = now_node;
  }
  if (last_node == NDN_INVALID_ID) return NULL; else return &(*nametree)[last_node];
}

nametree_entry_t*
ndn_nametree_at(ndn_nametree_t *self, ndn_table_id_t id){
  return &(*self)[id];
}

ndn_table_id_t
ndn_nametree_getid(ndn_nametree_t *self, nametree_entry_t* entry){
  return entry - &(*self)[0];
}
