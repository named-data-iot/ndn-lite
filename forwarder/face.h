/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef FORWARDER_FACE_H_
#define FORWARDER_FACE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "../ndn-enums.h"
#include "../ndn-constants.h"

#define container_of(ptr, type, member) \
  ((type *)((char *)(1 ? (ptr) : &((type *)0)->member) - offsetof(type, member)))

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup NDNFwdFace Face
 * @brief Abstract NDN network face.
 * @ingroup NDNFwd
 * @{
 */

struct ndn_face_intf;

/** Turn on the face.
 * @sa ndn_face_up
 */
typedef int (*ndn_face_intf_up)(struct ndn_face_intf* self);

/** Send out a packet.
 * @sa ndn_face_send
 */
typedef int (*ndn_face_intf_send)(struct ndn_face_intf* self,
                                  const uint8_t* packet, uint32_t size);

/** Shutdown the face temporarily.
 * @sa ndn_face_down
 */
typedef int (*ndn_face_intf_down)(struct ndn_face_intf* self);

/** Destructor.
 * @sa ndn_face_destroy
 */
typedef void (*ndn_face_intf_destroy)(struct ndn_face_intf* self);

/** Abstract NDN network face.
 *
 * An abstract base "class" for all faces.
 * Derived "classes" should implement the function ndn_face_intf#up, ndn_face_intf#send,
 * ndn_face_intf#down, and ndn_face_intf#destroy with platform-specific APIs.
 * Developers should assign the implementation of interfaces to function pointers in @c ndn_face_intf.
 * The assignment usually takes place in the face contrustion function.
 *
 * A minimum face implementation example is face/dummy-face.h .c
 * Real examples can be found in ndn-lite platform-specific platform packages.
 *
 * @attention @c ndn_face_intf should always be the first member of any face class.
 */
typedef struct ndn_face_intf {
  /** Turn on the face.
   * @sa ndn_face_up
   */
  ndn_face_intf_up up;

  /** Send out a packet.
   * @sa ndn_face_send
   */
  ndn_face_intf_send send;

  /** Shutdown the face temporarily.
   * @sa ndn_face_down
   */
  ndn_face_intf_down down;

  /** Destructor.
   * @sa ndn_face_destroy
   */
  ndn_face_intf_destroy destroy;

  /**
   * Unique Face ID.
   */
  ndn_table_id_t face_id;

  /** The state of the face.
   *
   * Currently not used by the forwarder.
   * Possible values: #NDN_FACE_STATE_DOWN, #NDN_FACE_STATE_UP, #NDN_FACE_STATE_DESTROYED.
   */
  uint8_t state;

  /**
   * The type of the face, reserved.
   *
   * Possible values: #NDN_FACE_TYPE_APP, #NDN_FACE_TYPE_NET, #NDN_FACE_TYPE_UNDEFINED
   */
  uint8_t type;
} ndn_face_intf_t;

/** Turn on the face.
 * @param[in, out] self The face to trun on.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 */
static inline int
ndn_face_up(ndn_face_intf_t* self)
{
  if (self->state != NDN_FACE_STATE_UP)
    return self->up(self);
  return 0;
}

/** Send out a packet.
 * @param[in, out] self The face through which to send.
 * @param[in] packet The encoded packet.
 * @param[in] size The size of @c packet.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 */
static inline int
ndn_face_send(ndn_face_intf_t* self, const uint8_t* packet, uint32_t size)
{
  if (self->state != NDN_FACE_STATE_UP)
    self->up(self);
  return self->send(self, packet, size);
}

/** Shutdown the face temporarily.
 * @param[in, out] self Input. The interface to turn off.
 * @return #NDN_SUCCESS if the call succeeded. The error code otherwise.
 */
static inline int
ndn_face_down(ndn_face_intf_t* self)
{
  return self->down(self);
}

/** Destructor.
 *
 * Destroy the face permanently.
 * @param[in, out] self The face to destroy.
 */
static inline void
ndn_face_destroy(ndn_face_intf_t* self)
{
  self->destroy(self);
}

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_FACE_H_
