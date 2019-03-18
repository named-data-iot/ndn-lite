/*
 * Copyright (C) 2018-2019 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

// NOTES: Any other modules should ONLY include this file.
// All functions declared in this file should be robust to wrong inputs.
// TODO: All possible retvals should be documented.

#ifndef FORWARDER_FORWARDER_H
#define FORWARDER_FORWARDER_H

#include "face.h"
#include "callback-funcs.h"
#include "../util/msg-queue.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: Document return values

/**@defgroup NDNFwd Forwarder
 * @brief A lite forwarder.
 */

/** @defgroup NDNFwdForwarder Forwarder Core
 * @ingroup NDNFwd
 * @{
 */

/** Initialize all components of the forwarder.
 */
void
ndn_forwarder_init(void);

/** Process event messages.
 *
 * This should be called at a fixed interval.
 */
void
ndn_forwarder_process(void);

/** Register a new face.
 *
 * The face should call this to get a face id during creation.
 * @param face [inout] The face to register
 * @note Application doesn't need to register faces manually.
 */
int
ndn_forwarder_register_face(ndn_face_intf_t* face);

/** Unregister a face.
 *
 * Remove @c face from FIB, PIT and face table.
 * The face should unregister itself during destruction.
 * Delete FIB or PIT entries if necessary.
 * @param face [inout] The face to unregister.
 * @note Application doesn't need to unregister faces manually.
 */
int
ndn_forwarder_unregister_face(ndn_face_intf_t* face);

/** Add a route into FIB.
 *
 * @param face [in] The face to forward.
 * @param prefix [in] The prefix of the route.
 * @param length [in] The length of @c prefix .
 */
int
ndn_forwarder_add_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length);

/** Remove a route from FIB.
 *
 * Removing the last route of a not registered FIB entry will delete the entry.
 * @param face [in] The face of the route.
 * @param prefix [in] The prefix of the route.
 * @param length [in] The length of @c prefix .
 */
int
ndn_forwarder_remove_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length);

/** Remove all routes of a prefix from FIB.
 *
 * Removing all routes and the FIB entry for a prefix.
 * @param prefix [in] The prefix.
 * @param length [in] The length of @c prefix .
 */
int
ndn_forwarder_remove_all_routes(uint8_t* prefix, size_t length);

/** Receive a packet from a face.
 *
 * Removing the last route of a FIB entry will delete the entry.
 * @param face [in, opt] The face of the route.
 * @param prefix [in] The prefix of the route.
 * @param length [in] The length of @c prefix .
 * @note Application doesn't need to call this manually.
 */
int
ndn_forwarder_receive(ndn_face_intf_t* face, uint8_t* packet, size_t length);

/** Register a prefix.
 *
 * A latter registration cancels the former one.
 * @param prefix [in] The prefix to register.
 * @param length [in] The length of @c prefix .
 * @param on_interest [in] The callback function when an interest comes.
 * @param userdata [in, opt] User-defined data, copied to @c on_interest .
 */
int
ndn_forwarder_register_prefix(uint8_t* prefix,
                              size_t length,
                              ndn_on_interest_func on_interest,
                              void* userdata);

/** Unregister a prefix.
 *
 * @param prefix [in] The prefix to register.
 * @param length [in] The length of @c prefix .
 */
int
ndn_forwarder_unregister_prefix(uint8_t* prefix, size_t length);

/** Express an interest.
 *
 * A repeated expression cancels the former expression with the same name.
 * Either @c on_data or @c on_timeout will be called only once.
 * @param interest [in] The interest to express.
 * @param length [in] The length of @c interest .
 * @param on_data [in] The callback function when a data comes.
 * @param on_timeout [in, opt] The callback function when times out.
 * @param userdata [in, opt] User-defined data, copied to @c on_data and @c on_timeout .
 */
int
ndn_forwarder_express_interest(uint8_t* interest,
                               size_t length,
                               ndn_on_data_func on_data,
                               ndn_on_timeout_func on_timeout,
                               void* userdata);

/** Produce a data packet.
 *
 * @param data [in] The data to produce.
 * @param length [in] The length of @c data .
 */
int
ndn_forwarder_put_data(uint8_t* data, size_t length);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_FORWARDER_H
