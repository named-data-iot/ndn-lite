/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include <sys/ioctl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "udp-face.h"
#include "ndn-lite/ndn-error-code.h"
#include "ndn-lite/ndn-constants.h"

static int
ndn_udp_face_up(struct ndn_face_intf* self);

static int
ndn_udp_face_down(struct ndn_face_intf* self);

static void
ndn_udp_face_destroy(ndn_face_intf_t* self);

static int
ndn_udp_face_send(ndn_face_intf_t* self, const uint8_t* packet, uint32_t size);

static ndn_udp_face_t*
ndn_udp_face_construct(
  in_addr_t local_addr,
  in_port_t local_port,
  in_addr_t remote_addr,
  in_port_t remote_port,
  bool multicast);

static void
ndn_udp_face_recv(void *self, size_t param_len, void *param);

/////////////////////////// /////////////////////////// ///////////////////////////

static int
ndn_udp_face_up(struct ndn_face_intf* self){
  ndn_udp_face_t* ptr = container_of(self, ndn_udp_face_t, intf);
  int iyes = 1, iflags;
  u_char ttl = 5;
  struct ip_mreq mreq;

  if(self->state == NDN_FACE_STATE_UP){
    return NDN_SUCCESS;
  }
  ptr->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(ptr->sock == -1){
    return NDN_UDP_FACE_SOCKET_ERROR;
  }
  setsockopt(ptr->sock, SOL_SOCKET, SO_REUSEADDR, &iyes, sizeof(int));
  //if(ioctl(ptr->sock, FIONBIO, (char *)&iyes) == -1){
  iflags = fcntl(ptr->sock, F_GETFL, 0);
  if(iflags == -1){
    ndn_face_down(self);
    return NDN_UDP_FACE_SOCKET_ERROR;
  }
  if(fcntl(ptr->sock, F_SETFL, iflags | O_NONBLOCK) == -1){
    ndn_face_down(self);
    return NDN_UDP_FACE_SOCKET_ERROR;
  }

  if(bind(ptr->sock, (struct sockaddr*)&ptr->local_addr, sizeof(ptr->local_addr)) == -1){
    ndn_face_down(self);
    return NDN_UDP_FACE_SOCKET_ERROR;
  }

  if(ptr->multicast){
    setsockopt(ptr->sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
  
    mreq.imr_interface = ptr->local_addr.sin_addr;
    mreq.imr_multiaddr = ptr->remote_addr.sin_addr;
    if(setsockopt(ptr->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1){
      ndn_face_down(self);
      return NDN_UDP_FACE_SOCKET_ERROR;
    }
  }

  ptr->process_event = ndn_msgqueue_post(ptr, ndn_udp_face_recv, 0, NULL);
  if(ptr->process_event == NULL){
    ndn_face_down(self);
    return NDN_FWD_MSGQUEUE_FULL;
  }

  self->state = NDN_FACE_STATE_UP;
  return NDN_SUCCESS;
}

static int
ndn_udp_face_down(struct ndn_face_intf* self){
  ndn_udp_face_t* ptr = (ndn_udp_face_t*)self;
  self->state = NDN_FACE_STATE_DOWN;

  if(ptr->sock != -1){
    close(ptr->sock);
    ptr->sock = -1;
  }

  if(ptr->process_event != NULL){
    ndn_msgqueue_cancel(ptr->process_event);
    ptr->process_event = NULL;
  }

  return NDN_SUCCESS;
}

static void
ndn_udp_face_destroy(ndn_face_intf_t* self){
  ndn_face_down(self);
  ndn_forwarder_unregister_face(self);
  free(self);
}

static int
ndn_udp_face_send(ndn_face_intf_t* self, const uint8_t* packet, uint32_t size){
  ndn_udp_face_t* ptr = (ndn_udp_face_t*)self;
  ssize_t ret;
  ret = sendto(ptr->sock, packet, size, 0, 
               (struct sockaddr*)&ptr->remote_addr, sizeof(ptr->remote_addr));
  if(ret != size){
    return NDN_UDP_FACE_SOCKET_ERROR;
  }else{
    return NDN_SUCCESS;
  }
}

static ndn_udp_face_t*
ndn_udp_face_construct(
  in_addr_t local_addr,
  in_port_t local_port,
  in_addr_t remote_addr,
  in_port_t remote_port,
  bool multicast)
{
  ndn_udp_face_t* ret;
  int iret;

  ret = (ndn_udp_face_t*)malloc(sizeof(ndn_udp_face_t));
  if(!ret){
    return NULL;
  }

  ret->intf.face_id = NDN_INVALID_ID;
  iret = ndn_forwarder_register_face(&ret->intf);
  if(iret != NDN_SUCCESS){
    free(ret);
    return NULL;
  }

  ret->intf.type = NDN_FACE_TYPE_NET;
  ret->intf.state = NDN_FACE_STATE_DOWN;
  ret->intf.up = ndn_udp_face_up;
  ret->intf.down = ndn_udp_face_down;
  ret->intf.send = ndn_udp_face_send;
  ret->intf.destroy = ndn_udp_face_destroy;

  ret->local_addr.sin_family = AF_INET;
  ret->local_addr.sin_port = local_port;
  ret->local_addr.sin_addr.s_addr = local_addr;
  memset(ret->local_addr.sin_zero, 0, sizeof(ret->local_addr.sin_zero));

  ret->remote_addr.sin_family = AF_INET;
  ret->remote_addr.sin_port = remote_port;
  ret->remote_addr.sin_addr.s_addr = remote_addr;
  memset(ret->remote_addr.sin_zero, 0, sizeof(ret->remote_addr.sin_zero));

  ret->sock = -1;
  ret->multicast = multicast;
  ret->process_event = NULL;
  ndn_face_up(&ret->intf);

  return ret;
}

ndn_udp_face_t*
ndn_udp_unicast_face_construct(
  in_addr_t local_addr,
  in_port_t local_port,
  in_addr_t remote_addr,
  in_port_t remote_port)
{
  return ndn_udp_face_construct(local_addr, local_port, remote_addr, remote_port, false);
}

ndn_udp_face_t*
ndn_udp_multicast_face_construct(
  in_addr_t local_addr,
  in_addr_t group_addr,
  in_port_t port)
{
  return ndn_udp_face_construct(local_addr, port, group_addr, port, true);
}

static void
ndn_udp_face_recv(void *self, size_t param_len, void *param){
  struct sockaddr_in client_addr;
  socklen_t addr_len;
  ssize_t size;
  int ret;
  ndn_udp_face_t* ptr = (ndn_udp_face_t*)self;

  while(true){
    size = recvfrom(ptr->sock, ptr->buf, sizeof(ptr->buf), 0,
                    (struct sockaddr*)&client_addr, &addr_len);
    if(size >= 0){
      // A packet recved
      ret = ndn_forwarder_receive(&ptr->intf, ptr->buf, size);
    }else if(size == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)){
      // No more packet
      break;
    }else{
      ndn_face_down(&ptr->intf);
      return;
    }
  }

  ptr->process_event = ndn_msgqueue_post(self, ndn_udp_face_recv, param_len, param);
}