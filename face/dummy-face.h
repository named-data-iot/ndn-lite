/*
 * Copyright (C) Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

/***********************************************************
 **  This Face Implementation is only for tests
 ************************************************************/

#ifndef NDN_DUMMY_FACE_H
#define NDN_DUMMY_FACE_H

#include "../forwarder/forwarder.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to represent a dummy face. This structure should only be declared for tests.
 */
typedef struct ndn_dummy_face {
  /**
   * The inherited interface abstraction.
   */
  ndn_face_intf_t intf;
} ndn_dummy_face_t;

/**
 * Construct the dummy face and initialize its state.
 * @param face. Input. The dummy face to be constructed.
 * @param face_id. Input. The face id to identity the dummy face.
 * @return the pointer to the constructed dummy face.
 */
ndn_dummy_face_t*
ndn_dummy_face_construct(ndn_dummy_face_t* face, uint16_t face_id);

#ifdef __cplusplus
}
#endif

#endif // NDN_DUMMY_FACE_H
