/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef FORWARDER_FIB_H_
#define FORWARDER_FIB_H_

#include "../util/bit-operations.h"
#include "callback-funcs.h"
#include "name-tree.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup NDNFwdFIB FIB
 * @brief Fowarding Infomation Base
 * @ingroup NDNFwd
 * @{
 */

/**
 * FIB entry.
 */
typedef struct ndn_fib_entry {
  /** A bitset recording all next hops.
   */
  ndn_bitset_t nexthop;

  /** OnOnterest callback function if registered.
   */
  ndn_on_interest_func on_interest;

  /** User defined data.
   */
  void* userdata;

  /** NameTree entry's ID.
   * #NDN_INVALID_ID if the entry is empty.
   */
  ndn_table_id_t nametree_id;
} ndn_fib_entry_t;

/**
 * Forwarding Information Base (FIB).
 */
typedef struct ndn_fib {
  ndn_nametree_t* nametree;
  ndn_table_id_t capacity;
  ndn_fib_entry_t slots[];
} ndn_fib_t;

#define NDN_FIB_RESERVE_SIZE(entry_count) \
  (sizeof(ndn_fib_t) + sizeof(ndn_fib_entry_t) * (entry_count))

void
ndn_fib_init(void* memory, ndn_table_id_t capacity, ndn_nametree_t* nametree);

void
ndn_fib_unregister_face(ndn_fib_t* self, ndn_table_id_t face_id);

ndn_fib_entry_t*
ndn_fib_find_or_insert(ndn_fib_t* self, uint8_t* prefix, size_t length);

ndn_fib_entry_t*
ndn_fib_find(ndn_fib_t* self, uint8_t* prefix, size_t length);

void
ndn_fib_remove_entry_if_empty(ndn_fib_t* self, ndn_fib_entry_t* entry);

ndn_fib_entry_t*
ndn_fib_prefix_match(ndn_fib_t* self, uint8_t* prefix, size_t length);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FIB_H
