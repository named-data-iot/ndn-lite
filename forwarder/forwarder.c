/*
 * Copyright (C) 2018-2019 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "forwarder.h"
#include "pit.h"
#include "fib.h"
#include "face-table.h"

#define NDN_FORWARDER_RESERVE_SIZE(nametree_size, facetab_size, fib_size, pit_size) \
  (NDN_NAMETREE_RESERVE_SIZE(nametree_size) + \
   NDN_FACE_TABLE_RESERVE_SIZE(facetab_size) + \
   NDN_FIB_RESERVE_SIZE(fib_size) + \
   NDN_PIT_RESERVE_SIZE(pit_size))

#define NDN_FORWARDER_DEFAULT_SIZE \
  NDN_FORWARDER_RESERVE_SIZE(NDN_NAMETREE_MAX_SIZE, \
                             NDN_FACE_TABLE_MAX_SIZE, \
                             NDN_FIB_MAX_SIZE, \
                             NDN_PIT_MAX_SIZE)

/**
 * NDN-Lite forwarder.
 * We will support content support in future versions.
 * The NDN forwarder is a singleton in an application.
 */
typedef struct ndn_forwarder {
  ndn_nametree_t* nametree;
  ndn_face_table_t* facetab;

  /**
   * The forwarding information base (FIB).
   */
  ndn_fib_t* fib;
  /**
   * The pending Interest table (PIT).
   */
  ndn_pit_t* pit;

  uint8_t memory[NDN_FORWARDER_DEFAULT_SIZE];
} ndn_forwarder_t;

static ndn_forwarder_t forwarder;
static bool forwarder_inited = false;