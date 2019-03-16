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
#include "face.h"
#include "name-tree.h"
#include "../util/uniform-time.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup NDNFwdPIT PIT
 * @brief Pending Interest Table
 * @ingroup NDNFwd
 * @{
 */

typedef void (*ndn_on_data_func)(const uint8_t* data, uint32_t data_size, void* userdata);
typedef void (*ndn_on_timeout_func)(void* userdata);

/**
 * PIT entry.
 */
typedef struct ndn_pit_entry {
  interest_options_t options;
  uint64_t incoming_faces;
  ndn_time_ms_t last_time;
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

void ndn_pit_init(void* memory, uint16_t capacity, ndn_nametree_t* nametree);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_PIT_H
