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

/** @defgroup NDNFwdNameTree Name Tree
 * @brief Name Tree
 * @ingroup NDNFwd
 * @{
 */

#define NDN_NAMETREE_FIB_TYPE 0
#define NDN_NAMETREE_PIT_TYPE 1

/**
 * NameTree node.
 */
typedef struct nametree_entry{
  /**
   * Name component of this node.
   */
  uint8_t val[NDN_NAME_COMPONENT_BLOCK_SIZE];

  /**
   * First child of this node.
   * #NDN_INVALID_ID if none.
   */
  uint16_t left_child;

  /**
   * Right brother of this node.
   * For root node, it points to a free list.
   * And a free node's right brother is the next free node.
   * #NDN_INVALID_ID if none.
   */
  uint16_t right_bro;

  /**
   * Corresponding PIT entry's id.
   * #NDN_INVALID_ID if none.
   */
  uint16_t pit_id;

  /**
   * Corresponding FIB entry's id.
   * #NDN_INVALID_ID if none.
   */
  uint16_t fib_id;
} nametree_entry_t;

typedef nametree_entry_t ndn_nametree_t[];

#define NDN_NAMETREE_RESERVE_SIZE(entry_count) (sizeof(nametree_entry_t) * (entry_count))

void
ndn_nametree_init(void* memory, uint16_t capacity);

nametree_entry_t*
ndn_nametree_find_or_insert(ndn_nametree_t* nametree, uint8_t name[], size_t len);

nametree_entry_t*
ndn_nametree_prefix_match(ndn_nametree_t* nametree, uint8_t name[], size_t len, int type);

nametree_entry_t*
ndn_nametree_find(ndn_nametree_t *nametree, uint8_t name[], size_t len);

/*@}*/

#endif