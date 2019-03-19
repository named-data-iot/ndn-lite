/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_PIT_H_
#define FORWARDER_PIT_H_
<<<<<<< HEAD
#include "../encode/forwarder-helper.h"
#include "../util/bit-operations.h"
=======

#include "../encode/interest.h"
#include "../util/timer.h"
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee
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
<<<<<<< HEAD
  interest_options_t options;
  uint64_t incoming_faces;
  ndn_time_ms_t last_time;
  ndn_time_ms_t express_time;
  ndn_on_data_func on_data;
  ndn_on_timeout_func on_timeout;
  void* userdata;
  uint16_t nametree_id;
=======
  /**
   * The name of representative Interest.
   * A name with components_size < 0 indicates an empty entry.
   */
  ndn_buffer_t interest_buffer;

  /**
   * Collection of incoming faces.
   */
  ndn_face_intf_t* incoming_face[NDN_MAX_FACE_PER_PIT_ENTRY];

  /**
   * The count of incoming faces.
   */
  uint8_t incoming_face_size;

  /**
   * @todo How to timeout?
   */
   ndn_timer_t timer;
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee
} ndn_pit_entry_t;

/**
* PIT class.
*/
typedef struct ndn_pit{
  ndn_nametree_t* nametree;
  uint16_t capacity;
  ndn_pit_entry_t slots[];
}ndn_pit_t;

#define NDN_PIT_RESERVE_SIZE(entry_count) \
  (sizeof(ndn_pit_t) + sizeof(ndn_pit_entry_t) * (entry_count))

void
ndn_pit_init(void* memory, uint16_t capacity, ndn_nametree_t* nametree);

void
ndn_pit_unregister_face(ndn_pit_t* self, uint16_t face_id);

int
ndn_pit_entry_add_incoming_face(ndn_pit_entry_t* entry, ndn_face_intf_t* face);

<<<<<<< HEAD
//set each components in a pit entry
void ndn_pit_set_entry(ndn_pit_entry_t *entry,
                  interest_options_t options,
                  uint64_t incoming_faces,
                  ndn_time_ms_t last_time,
                  ndn_time_ms_t express_time,
                  ndn_on_data_func on_data,
                  ndn_on_timeout_func on_timeout,
                  void* userdata,
                  uint16_t nametree_id);

//clean a pit entry, set nametree_id to NDN_INVALID_ID and others to 0.
void ndn_pit_refresh_entry(ndn_pit_entry_t *entry);

ndn_pit_entry_t*
ndn_pit_find_or_insert(ndn_pit_t* self, uint8_t* name, size_t length);

ndn_pit_entry_t*
ndn_pit_find(ndn_pit_t* self, uint8_t* prefix, size_t length);

ndn_pit_entry_t*
ndn_pit_prefix_match(ndn_pit_t* self, uint8_t* prefix, size_t length);

void
ndn_pit_remove_entry(ndn_pit_t* self, ndn_pit_entry_t* entry);

/*@}*/

=======
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee
#ifdef __cplusplus
}
#endif

#endif // FORWARDER_PIT_H
