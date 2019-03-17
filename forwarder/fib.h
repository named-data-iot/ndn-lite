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

//unregister a face from pit table.
void ndn_face_unregister_from_fib(ndn_fib_t* fib, ndn_face_intf_t* face);

//clean a fib entry, set nametree_id to NDN_INVALID_ID and others to 0.
void refresh_fib_entry(ndn_fib_entry_t *entry);

//create a new fib entry in fib table.
//fib (input): header of pit table
//offset (input): the position of nametree entry corresponding to this newly created fib entry. 
//                This value will be filled in the field "nametree_id".
//output: the position of this newly created fib entry in the fib table.
//        This value is used for fill in the field "fib_id" in the corresponding nametree entry.
int ndn_fib_add_new_entry(ndn_fib_t* fib , int offset);

//set each components in a fib entry
void set_fib_entry(ndn_fib_entry_t *entry,
                  ndn_bitset_t nexthop,
                  ndn_on_interest_func on_interest,
                  void* userdata,
                  uint16_t nametree_id);

//get the pointer of fib entry corresponding to given prefix. if no such an entry, create a new one.
//return the fib entry corresponding to prefix.
//fib (input): header of fib table.
//nametree (input): header of nametree.
//prefix (input): name prefix.
//length (input): length of name prefix.
//output: pointer of fib entry corresponding to given prefix.
ndn_fib_entry_t*
ndn_get_fib_entry(ndn_fib_t* fib, ndn_nametree_t* nametree, uint8_t* prefix, size_t length);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FIB_H
