/*
 * Copyright (C) 2019 Xinyu Ma, Yu Guan
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_NAME_TREE_H
#define FORWARDER_NAME_TREE_H

#include "../ndn-constants.h"
#include <stdint.h>
#include <stddef.h>

#define NDN_NAMETREE_INVALID_ID 0xFFFF

typedef struct nametree_entry{
  uint8_t val[NDN_NAME_COMPONENT_BLOCK_SIZE];
  uint16_t left_child;
  uint16_t right_bro;
  uint16_t pit_id;
  uint16_t fib_id;
} nametree_entry_t;
typedef struct ndn_nametree{
  size_t capacity;
  size_t size;
  nametree_entry_t root[];
}ndn_nametree_t;

ndn_nametree_t*
ndn_nametree_init(size_t capacity);

uint16_t
ndn_nametree_find_or_insert(ndn_nametree_t* self, uint8_t name[], size_t len);

uint16_t
ndn_nametree_fib_prefix_match(ndn_nametree_t* self, uint8_t name[], size_t len);

#endif