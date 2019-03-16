/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FIB_H_
#define FORWARDER_FIB_H_

#include "../util/bit-operations.h"
#include "name-tree.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup NDNFwdFIB FIB
 * @brief Fowarding Infomation Base
 * @ingroup NDNFwd
 * @{
 */

typedef int (*ndn_on_interest_func)(const uint8_t* interest,
                                    uint32_t interest_size,
                                    void* userdata);

/**
 * FIB entry.
 */
typedef struct ndn_fib_entry {
  ndn_bitset_t nexthop;
  ndn_on_interest_func on_interest;
  void* userdata;
  uint16_t nametree_id;
} ndn_fib_entry_t;

/**
 * Forwarding Information Base (FIB) class.
 */
typedef struct ndn_fib{
  ndn_nametree_t* nametree;
  uint16_t capacity;
  ndn_fib_entry_t slots[];
}ndn_fib_t;

#define NDN_FIB_RESERVE_SIZE(entry_count) \
  (sizeof(ndn_fib_t) + sizeof(ndn_fib_entry_t) * (entry_count))

void ndn_fib_init(void* memory, uint16_t capacity, ndn_nametree_t* nametree);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FIB_H
