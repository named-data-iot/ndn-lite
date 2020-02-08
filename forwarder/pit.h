/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef FORWARDER_PIT_H_
#define FORWARDER_PIT_H_
#include "../encode/forwarder-helper.h"
#include "../util/bit-operations.h"
#include "face.h"
#include "name-tree.h"
#include "callback-funcs.h"
#include "../util/uniform-time.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup NDNFwdPIT PIT
 * @brief Pending Interest Table
 * @ingroup NDNFwd
 * @{
 */

/**
 * PIT entry.
 */
typedef struct ndn_pit_entry {
  /** Interest Options.
   */
  interest_options_t options;

  /** Faces received this Interest.
   * Used to forward corresponding Data.
   */
  uint64_t incoming_faces;

  /** Faces sent out this Interest.
   * Used to suppress Interest forwarding.
   */
  uint64_t outgoing_faces;

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

  /** OnTimeout callback if the application expressed this Interest.
   */
  ndn_on_timeout_func on_timeout;

  /** User defined data.
   */
  void* userdata;

  /** NameTree entry's ID.
   * #NDN_INVALID_ID if the entry is empty.
   */
  ndn_table_id_t nametree_id;
} ndn_pit_entry_t;

/**
* Forwarding Information Base (FIB).
*/
typedef struct ndn_pit{
  ndn_nametree_t* nametree;
  ndn_table_id_t capacity;
  ndn_pit_entry_t slots[];
}ndn_pit_t;

#define NDN_PIT_RESERVE_SIZE(entry_count) \
  (sizeof(ndn_pit_t) + sizeof(ndn_pit_entry_t) * (entry_count))

void
ndn_pit_init(void* memory, ndn_table_id_t capacity, ndn_nametree_t* nametree);

void
ndn_pit_unregister_face(ndn_pit_t* self, ndn_table_id_t face_id);

ndn_pit_entry_t*
ndn_pit_find_or_insert(ndn_pit_t* self, uint8_t* name, size_t length);

ndn_pit_entry_t*
ndn_pit_find(ndn_pit_t* self, uint8_t* prefix, size_t length);

ndn_pit_entry_t*
ndn_pit_prefix_match(ndn_pit_t* self, uint8_t* prefix, size_t length);

void
ndn_pit_remove_entry(ndn_pit_t* self, ndn_pit_entry_t* entry);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_PIT_H
