/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef FORWARDER_CS_H_
#define FORWARDER_CS_H_
#include "../encode/forwarder-helper.h"
#include "../util/bit-operations.h"
#include "face.h"
#include "name-tree.h"
#include "callback-funcs.h"
#include "../util/uniform-time.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup NDNFwdCS CS
 * @brief Content Store
 * @ingroup NDNFwd
 * @{
 */

/**
 * CS entry.
 */
typedef struct ndn_cs_entry {
  /** Interest Options.
   */
  interest_options_t options;

  /** Timestamp for last time the forwarder received this Interest.
   */
  ndn_time_ms_t last_time;

  /** Timestamp when the application expressed this Interest.
   * 0 If it's received from a face.
   */
  ndn_time_ms_t express_time;

  /** OnData callback if the application expressed this Interest.
   */
  ndn_on_data_func on_data;

  /** User defined data.
   */
  void* userdata;

  /** Content of this entry.
   */
  uint8_t* content;

  /** Size of content
   */
  size_t content_len;

  /** Relative time until this entry is fresh
   */
  ndn_time_ms_t fresh_until;

  /** NameTree entry's ID.
   * #NDN_INVALID_ID if the entry is empty.
   */
  ndn_table_id_t nametree_id;
} ndn_cs_entry_t;

/**
* Content Store (CS).
*/
typedef struct ndn_cs{
  ndn_nametree_t* nametree;
  ndn_table_id_t capacity;
  ndn_cs_entry_t slots[];
}ndn_cs_t;

#define NDN_CS_RESERVE_SIZE(entry_count) \
  (sizeof(ndn_cs_t) + sizeof(ndn_cs_entry_t) * (entry_count))

void
ndn_cs_init(void* memory, ndn_table_id_t capacity, ndn_nametree_t* nametree);

void
ndn_cs_remove_entry(ndn_cs_t* self, ndn_cs_entry_t* entry);

ndn_cs_entry_t*
ndn_cs_find_or_insert(ndn_cs_t* self, uint8_t* name, size_t length);

ndn_cs_entry_t*
ndn_cs_find(ndn_cs_t* self, uint8_t* prefix, size_t length);

ndn_cs_entry_t*
ndn_cs_prefix_match(ndn_cs_t* self, uint8_t* prefix, size_t length);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_CS_H
