/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FIB_H_
#define FORWARDER_FIB_H_

#include "../encode/interest.h"
#include "face.h"

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
  /**
   * The name prefix.
   * A name with <tt> ndn_name_t#components_size < 0 </tt> indicates an empty entry.
   */
  ndn_name_t name_prefix;

  /**
   * The next-hop record.
   * @note Only one next-hop record per entry is allowed in NDN-Lite.
   */
  ndn_face_intf_t* next_hop;

  /**
   * The cost to the next-hop.
   */
  uint8_t cost;
} ndn_fib_entry_t;

/**
 * Forwarding Information Base (FIB) class.
 */
typedef ndn_fib_entry_t ndn_fib_t[NDN_FIB_MAX_SIZE];

/**
 * Delete a FIB entry.
 * @param entry Input. The FIB entry.
 */
static inline void
fib_entry_delete(ndn_fib_entry_t* entry)
{
  entry->name_prefix.components_size = NDN_FWD_INVALID_NAME_SIZE;
}

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FIB_H
