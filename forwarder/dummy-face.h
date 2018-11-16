/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef dummy_face_h
#define dummy_face_h

#include "face.h"

#define NDN_DUMMY_FACE_BUFFER_SIZE 512

extern const ndn_face_intf_t ndn_dummy_face_klass;
#define NDN_KLASS_DUMMY_FACE  (&ndn_dummy_face_klass)

void
dummy_face_init(ndn_face_t* self);

#endif /* dummy_face_h */
