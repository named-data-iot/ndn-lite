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

void
ndn_forwarder_init(void)
{
  
}

//add a face into face table
int
ndn_forwarder_register_face(ndn_face_intf_t* face)
{
  if (face == NULL) return NDN_FWD_INVALID_FACE;
  int ret = ndn_facetab_register(forwarder.facetab, face);
  if (ret == NDN_INVALID_ID) return NDN_FWD_FACE_FULL;
  return NDN_SUCCESS;
}

//remove a face from face table, pit and fib
int
ndn_forwarder_unregister_face(ndn_face_intf_t* face)
{
  if (face == NULL) return NDN_FWD_INVALID_FACE;
  ndn_face_unregister_from_fib(forwarder.fib, face->face_id);
  ndn_face_unregister_from_pit(forwarder.pit, face->face_id);
  ndn_facetab_unregister(forwarder.facetab, face->face_id);
  return NDN_SUCCESS;
}

//add a route into fib
int
ndn_forwarder_add_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length)
{
  if (face == NULL) return NDN_FWD_INVALID_FACE;
  ndn_fib_entry_t* fib_entry = ndn_get_fib_entry(forwarder.fib, forwarder.nametree, prefix, length);
  if (fib_entry == NULL) return NDN_FWD_NO_MEM;
  bitset_set(fib_entry -> nexthop , face -> face_id);
  return NDN_SUCCESS;
}

//remove a route from fib
int
ndn_forwarder_remove_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length)
{
  if (face == NULL) return NDN_FWD_INVALID_FACE;
  ndn_fib_entry_t* fib_entry = ndn_get_fib_entry(forwarder.fib, forwarder.nametree, prefix, length);
  if (fib_entry == NULL) return NDN_FWD_NO_MEM;
  bitset_unset(fib_entry -> nexthop , face -> face_id);
  return NDN_SUCCESS;
}

//remove all routes of a fib entry.
int
ndn_forwarder_remove_all_routes(uint8_t* prefix, size_t length)
{
  ndn_fib_entry_t* fib_entry = ndn_get_fib_entry(forwarder.fib, forwarder.nametree, prefix, length);
  if (fib_entry == NULL) return NDN_FWD_NO_MEM;
  fib_entry -> nexthop = 0;
  return NDN_SUCCESS;
}

//receive a packet from face
int
ndn_forwarder_receive(ndn_face_intf_t* face, const uint8_t* packet, size_t length)
{
  //interest?data
  //
}

//register a prefix
//shanxigy: nexthop bitset is set to 0.
int
ndn_forwarder_register_prefix(uint8_t* prefix,
                              size_t length,
                              ndn_on_interest_func on_interest,
                              void* userdata)
{
  nametree_entry_t* entry = ndn_nametree_find_or_insert(forwarder.nametree, prefix, length);
  ndn_fib_entry_t* fib_entry = ndn_get_fib_entry(forwarder.fib, forwarder.nametree, prefix, length);
  if (fib_entry == NULL) return NDN_FWD_NO_MEM;
  set_fib_entry(fib_entry, 0, on_interest, userdata, entry - forwarder.nametree);
  return NDN_SUCCESS;
}

//unregister a prefix
int
ndn_forwarder_unregister_prefix(uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_find_or_insert(forwarder.nametree, prefix, length);
  if (entry == NULL) return NDN_FWD_NO_MEM;
  if (entry -> fib_id == NDN_INVALID_ID) return NDN_SUCCESS;
  refresh_fib_entry(forwarder.fib -> slots[entry -> fib_id]);
  entry -> fib_id = NDN_INVALID_ID;
  return NDN_SUCCESS;
}

//express an interest
int
ndn_forwarder_express_interest(const uint8_t* interest,
                               size_t length,
                               ndn_on_data_func on_data,
                               ndn_on_timeout_func on_timeout,
                               void* userdata)
{
  ndn_pit_entry_t* pit_entry = ndn_get_pit_entry(forwarder.pit, forwarder.nametree, interest, length);
  if (pit_entry == NULL) return NDN_FWD_NO_MEM;
  pit_entry -> on_data = on_data;
  pit_entry -> on_timeout = on_timeout;
  pit_entry -> userdata = userdata;
  return ndn_forwarder_receive(NULL, interest, length);
}

//produce a data
int
ndn_forwarder_put_data(const uint8_t* data, size_t length)
{
  return ndn_forwarder_receive(NULL, data, length);
}
