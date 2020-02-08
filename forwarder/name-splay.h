/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef FORWARDER_NAME_SPLAY_H
#define FORWARDER_NAME_SPLAY_H

#include "../ndn-constants.h"
#include <stdint.h>
#include <stddef.h>

// TODO: Rename; use compilation flags

#ifdef __cplusplus
extern "C" {
#endif

enum NDN_NAMETREE_ENTRY_TYPE{
  NDN_NAMETREE_FIB_TYPE,
  NDN_NAMETREE_PIT_TYPE,

  NDN_NAMETREE_ENTRY_TYPE_CNT
};


typedef struct nametree_entry{
  uint8_t val[NDN_NAME_COMPONENT_BLOCK_SIZE];
  struct nametree_entry* sub; /// Subtree
  struct nametree_entry* cop[2]; /// Child or parent
  ndn_table_id_t pit_id;
  ndn_table_id_t fib_id;
} nametree_entry_t;

typedef struct ndn_nametree{
  nametree_entry_t *nil, *root;
  nametree_entry_t pool[];
}ndn_nametree_t;

#define NDN_NAMETREE_RESERVE_SIZE(entry_count) \
  (sizeof(nametree_entry_t) * (entry_count) + sizeof(ndn_nametree_t))

void
ndn_nametree_init(void* memory, ndn_table_id_t capacity);

nametree_entry_t*
ndn_nametree_find_or_insert(ndn_nametree_t *self, uint8_t name[], size_t len);

nametree_entry_t*
ndn_nametree_find(ndn_nametree_t *self, uint8_t name[], size_t len);

nametree_entry_t*
ndn_nametree_prefix_match(
  ndn_nametree_t *self,
  uint8_t name[],
  size_t len,
  enum NDN_NAMETREE_ENTRY_TYPE entry_type);

nametree_entry_t*
ndn_nametree_at(ndn_nametree_t *self, ndn_table_id_t id);

ndn_table_id_t
ndn_nametree_getid(ndn_nametree_t *self, nametree_entry_t* entry);

#ifdef __cplusplus
}
#endif

#endif