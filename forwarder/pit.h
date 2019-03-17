/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_PIT_H_
#define FORWARDER_PIT_H_
#include "../encode/new-interest.h"
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
  interest_options_t options;
  uint64_t incoming_faces;
  ndn_time_ms_t last_time;
  ndn_time_ms_t express_time;
  ndn_on_data_func on_data;
  ndn_on_timeout_func on_timeout;
  void* userdata;
  uint16_t nametree_id;
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

//create a new pit entry in pit table.
//pit (input): header of pit table
//offset (input): the position of nametree entry corresponding to this newly created pit entry. 
//                This value will be filled in the field "nametree_id".
//output: the position of this newly created pit entry in the pit table.
//        This value is used for fill in the field "pit_id" in the corresponding nametree entry.
int ndn_pit_add_new_entry(ndn_pit_t* pit , int offset);

//get the pointer of pit entry corresponding to given prefix. if no such an entry, create a new one.
//return the pit entry corresponding to prefix.
//self (input): pointer of pit table.
//prefix (input): name prefix.
//length (input): length of name prefix.
//output: pointer of pit entry corresponding to given prefix.
ndn_pit_entry_t*
ndn_pit_find_or_insert(ndn_pit_t* self, uint8_t* prefix, size_t length);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_PIT_H
