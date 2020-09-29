/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef FORWARDER_FORWARDER_H
#define FORWARDER_FORWARDER_H

#include "face.h"
#include "name-tree.h"
#include "pit.h"
#include "fib.h"
#include "face-table.h"
#include "../encode/name.h"
#include "../encode/interest.h"
#include "callback-funcs.h"
#include "../util/msg-queue.h"

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

#ifdef __cplusplus
extern "C" {
#endif

// TODO: Add support of content store and make it a modular component: can be realized with RAM, ROM, etc. the size is configurable.

/**
 * NDN-Lite forwarder.
 * We will support content store in future versions.
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

/**@defgroup NDNFwd Forwarder
 * @brief A lite forwarder.
 */

/** @defgroup NDNFwdForwarder Forwarder Core
 * @brief The forwarder core.
 * @ingroup NDNFwd
 * @{
 */

/** Initialize all components of the forwarder.
 */
void
ndn_forwarder_init(void);

/** Returns the forwarder as a pointer
 */
const ndn_forwarder_t*
ndn_forwarder_get(void);

/** Process event messages.
 *
 * This should be called at a fixed interval.
 */
void
ndn_forwarder_process(void);

/** Register a new face.
 *
 * The face should call this to get a face id during creation.
 * @param[in, out] face The face to register.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_FWD_NO_EFFECT @c face already has an ID.
 * @retval #NDN_FWD_FACE_TABLE_FULL FaceTable is full. See also #NDN_FACE_TABLE_MAX_SIZE.
 * @note The application doesn't need to register faces manually.
 * @pre <tt>face->face_id == #NDN_INVALID_ID</tt>
 */
int
ndn_forwarder_register_face(ndn_face_intf_t* face);

/** Unregister a face.
 *
 * Remove @c face from FIB, PIT and face table.
 * The face should unregister itself during destruction.
 * Delete FIB or PIT entries if necessary.
 * @param[in, out] face The face to unregister.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_FWD_NO_EFFECT @c face is not in FaceTable now.
 * @note The application doesn't need to unregister faces manually.
 * @post <tt>face->face_id == #NDN_INVALID_ID</tt>
 */
int
ndn_forwarder_unregister_face(ndn_face_intf_t* face);

/** Add a route into FIB.
 *
 * @param[in] face The face to forward.
 * @param[in] prefix The prefix of the route.
 * @param[in] length The length of @c prefix.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_FWD_FIB_FULL FIB or NameTree is full. See also #NDN_FIB_MAX_SIZE,
 *                          #NDN_NAMETREE_MAX_SIZE.
 */
int
ndn_forwarder_add_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length);

int
ndn_forwarder_add_route_by_str(ndn_face_intf_t* face, const char* prefix, size_t length);

int
ndn_forwarder_add_route_by_name(ndn_face_intf_t* face, const ndn_name_t* prefix);

/** Remove a route from FIB.
 *
 * Removing the last route of a not registered FIB entry will delete the entry.
 * @param[in] face The face of the route.
 * @param[in] prefix The prefix of the route.
 * @param[in] length The length of @c prefix .
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_FWD_NO_EFFECT Currently @c prefix has no route.
 */
int
ndn_forwarder_remove_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length);

/** Remove all routes of a prefix from FIB.
 *
 * Removing all routes and the FIB entry for a prefix.
 * @param[in] prefix The prefix.
 * @param[in] length The length of @c prefix.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_FWD_NO_EFFECT Currently @c prefix has no route.
 */
int
ndn_forwarder_remove_all_routes(uint8_t* prefix, size_t length);

/** Receive a packet from a face.
 *
 */
int
ndn_forwarder_receive(ndn_face_intf_t* face, uint8_t* packet, size_t length);

/** Register a prefix.
 *
 * A latter registration cancels the former one.
 * @param[in] prefix The prefix to register.
 * @param[in] length The length of @c prefix .
 * @param[in] on_interest The callback function when an interest comes.
 * @param[in] userdata [Optional] User-defined data, copied to @c on_interest.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_FWD_FIB_FULL FIB or NameTree is full. See also #NDN_FIB_MAX_SIZE,
 *                          #NDN_NAMETREE_MAX_SIZE.
 */
int
ndn_forwarder_register_prefix(uint8_t* prefix, size_t length,
                              ndn_on_interest_func on_interest,
                              void* userdata);

int
ndn_forwarder_register_name_prefix(const ndn_name_t* prefix,
                                   ndn_on_interest_func on_interest,
                                   void* userdata);

/** Unregister a prefix.
 *
 * @param[in] prefix The prefix to register.
 * @param[in] length The length of @c prefix.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_FWD_NO_EFFECT Currently @c prefix is not registered.
 */
int
ndn_forwarder_unregister_prefix(uint8_t* prefix, size_t length);

/** Express an interest.
 *
 * A repeated expression cancels the former expression with the same name.
 * Either @c on_data or @c on_timeout will be called only once.
 * @param[in] interest The interest to express.
 * @param[in] length The length of @c interest.
 * @param[in] on_data The callback function when a data comes.
 * @param[in] on_timeout [Optional] The callback function when times out.
 * @param[in] userdata [Optional] User-defined data, copied to @c on_data and @c on_timeout.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 * @retval #NDN_FWD_PIT_FULL PIT or NameTree is full. See also #NDN_PIT_MAX_SIZE,
 *                          #NDN_NAMETREE_MAX_SIZE.
 */
int
ndn_forwarder_express_interest(uint8_t* interest, size_t length,
                               ndn_on_data_func on_data,
                               ndn_on_timeout_func on_timeout,
                               void* userdata);

int
ndn_forwarder_express_interest_struct(ndn_interest_t* interest,
                                      ndn_on_data_func on_data,
                                      ndn_on_timeout_func on_timeout,
                                      void* userdata);

/** Produce a data packet.
 *
 * @param[in] data The data to produce.
 * @param[in] length The length of @c data.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 */
int
ndn_forwarder_put_data(uint8_t* data, size_t length);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FORWARDER_H
