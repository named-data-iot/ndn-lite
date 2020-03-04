/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_UDP_FACE_H_
#define NDN_UDP_FACE_H_

#include <netinet/in.h>
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/util/msg-queue.h"
#include "../adapt-consts.h"

#ifdef __cplusplus
extern "C" {
#endif

// This face is different because we can create multiple faces safely

// Generally MTU < 2048
// Given that we don't cache
#define NDN_UDP_BUFFER_SIZE 4096

/**
 * Udp face
 */
typedef struct ndn_udp_face {
  /**
   * The inherited interface.
   */
  ndn_face_intf_t intf;

  struct sockaddr_in local_addr;
  struct sockaddr_in remote_addr;
  struct ndn_msg* process_event;
  int sock;
  bool multicast;
  uint8_t buf[NDN_UDP_BUFFER_SIZE];
} ndn_udp_face_t;

ndn_udp_face_t*
ndn_udp_unicast_face_construct(
  in_addr_t local_addr,
  in_port_t local_port,
  in_addr_t remote_addr,
  in_port_t remote_port);

ndn_udp_face_t*
ndn_udp_multicast_face_construct(
  in_addr_t local_addr,
  in_addr_t group_addr,
  in_port_t port);

#ifdef __cplusplus
}
#endif

#endif