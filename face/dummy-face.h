/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
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
 * @return the pointer to the constructed dummy face.
 */
ndn_dummy_face_t*
ndn_dummy_face_construct();

#ifdef __cplusplus
}
#endif

#endif // NDN_DUMMY_FACE_H
