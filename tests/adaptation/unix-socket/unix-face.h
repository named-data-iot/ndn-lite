/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_UNIX_FACE_H_
#define NDN_UNIX_FACE_H_

#include <sys/socket.h>
#include <sys/un.h>
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/util/msg-queue.h"
#include "../adapt-consts.h"

#ifdef __cplusplus
extern "C" {
#endif

// Generally MTU < 2048
// Given that we don't cache
#define NDN_UNIX_BUFFER_SIZE 4096

/**
 * Unix Socket face (client)
 */
typedef struct ndn_unix_face {
  /**
   * The inherited interface.
   */
  ndn_face_intf_t intf;

  struct sockaddr_un addr;
  struct ndn_msg* process_event;
  int sock;

  uint8_t buf[NDN_UNIX_BUFFER_SIZE];
  uint32_t offset;

  bool client;
} ndn_unix_face_t;

ndn_unix_face_t*
ndn_unix_face_construct(const char* addr, bool client);

#ifdef __cplusplus
}
#endif

#endif