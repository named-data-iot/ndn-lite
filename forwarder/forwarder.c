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

void
ndn_forwarder_init(void)
{
  ndn_facetab_init(&forwarder.facetab, NDN_FACE_TABLE_MAX_SIZE);
}

//add a face into face table
int
ndn_forwarder_register_face(ndn_face_intf_t* face)
{
  if (face == NULL) return -1;
  ndn_facetab_register(&forwarder.facetab, face);
  return NDN_SUCCEED;
}

//remove a face from face table, pit and fib
int
ndn_forwarder_unregister_face(ndn_face_intf_t* face)
{
  ndn_face_unregister_from_fib()
  ndn_facetab_unregister(&forwarder.facetab, face->face_id)
}

//add a route into fib
int
ndn_forwarder_add_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length);

//remove a route from fib
int
ndn_forwarder_remove_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length);

//remove all routes of a fib entry.
int
ndn_forwarder_remove_all_routes(uint8_t* prefix, size_t length);

//receive a packet from face
int
ndn_forwarder_receive(ndn_face_intf_t* face, const uint8_t* packet, size_t length);

//register a prefix
int
ndn_forwarder_register_prefix(uint8_t* prefix,
                              size_t length,
                              ndn_on_data_func on_data,
                              ndn_on_timeout_func on_timeout,
                              void* userdata);

//unregister a prefix
int
ndn_forwarder_unregister_prefix(uint8_t* prefix, size_t length);

//express an interest
int
ndn_forwarder_express_interest(const uint8_t* interest,
                               size_t length,
                               ndn_on_interest_func on_interest,
                               void* userdata);

//produce a data
int
ndn_forwarder_put_data(const uint8_t* data, size_t length);