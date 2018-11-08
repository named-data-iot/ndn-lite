//
//  dummy_face.h
//  riot-forwarder
//
//  Created by UCLA on 10/31/18.
//  Copyright © 2018 UCLA. All rights reserved.
//

#ifndef dummy_face_h
#define dummy_face_h

#include "face.h"

#define NDN_DUMMY_FACE_BUFFER_SIZE 512

extern const ndn_iface_t ndn_dummy_face_klass;
#define NDN_KLASS_DUMMY_FACE  (&ndn_dummy_face_klass)

void
dummy_face_init(ndn_face_t* self);

#endif /* dummy_face_h */
