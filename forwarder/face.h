/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_FACE_H_
#define FORWARDER_FACE_H_

#ifdef __cplusplus
extern "C" {
#endif

enum {
  NDN_FACE_UP, // available face
  NDN_FACE_DOWN, // temporally down
  NDN_FACE_CLOSED, // closed face
  NDN_FACE_FAILED, // closed caused by failure(s)
};

enum {
  NDN_FACE_LOCAL, // connects to local process
  NDN_FACE_REMOTE, // connects to network
};

typedef struct ndn_face {
  uint16_t face_id;
  uint8_t state;
  uint8_t type;

  uint8_t local_uri[10];
  uint8_t remote_uri[10];
} ndn_face_t;

typedef ndn_face_t[NDN_FACE_TABLE_MAX_SIZE] ndn_face_table_t;

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_FACE_H_
