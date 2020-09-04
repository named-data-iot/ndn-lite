/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "unix-face.h"
#include "ndn-lite/ndn-error-code.h"
#include "ndn-lite/ndn-constants.h"
#include "ndn-lite/encode/forwarder-helper.h"

static int
ndn_unix_face_up(struct ndn_face_intf* self);

static int
ndn_unix_client_face_up(struct ndn_face_intf* self);

static int
ndn_unix_server_face_up(struct ndn_face_intf* self);

static int
ndn_unix_face_down(struct ndn_face_intf* self);

static int
ndn_unix_slave_face_down(struct ndn_face_intf* self);

static void
ndn_unix_face_destroy(ndn_face_intf_t* self);

static int
ndn_unix_face_send(ndn_face_intf_t* self, const uint8_t* packet, uint32_t size);

static void
ndn_unix_face_recv(void *self, size_t param_len, void *param);

static void
ndn_unix_face_accept(void *self, size_t param_len, void *param);

static ndn_unix_face_t*
ndn_unix_slave_face_construct(int sock);

/////////////////////////// /////////////////////////// ///////////////////////////

static int
ndn_unix_face_up(struct ndn_face_intf* self){
  ndn_unix_face_t* ptr = container_of(self, ndn_unix_face_t, intf);
  int iflags;

  ptr->sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if(ptr->sock == -1){
    return NDN_UNIX_FACE_SOCKET_ERROR;
  }

  iflags = fcntl(ptr->sock, F_GETFL, 0);
  if(iflags == -1){
    ndn_face_down(self);
    return NDN_UNIX_FACE_SOCKET_ERROR;
  }
  if(fcntl(ptr->sock, F_SETFL, iflags | O_NONBLOCK) == -1){
    ndn_face_down(self);
    return NDN_UNIX_FACE_SOCKET_ERROR;
  }

  return NDN_SUCCESS;
}

static int
ndn_unix_client_face_up(struct ndn_face_intf* self){
  ndn_unix_face_t* ptr = container_of(self, ndn_unix_face_t, intf);
  int ret = 0;

  if(self->state == NDN_FACE_STATE_UP){
    return NDN_SUCCESS;
  }
  ret = ndn_unix_face_up(self);
  if(ret != NDN_SUCCESS){
    return ret;
  }

  if(connect(ptr->sock, (struct sockaddr*)&ptr->addr, sizeof(ptr->addr)) == -1){
    ndn_face_down(self);
    return NDN_UNIX_FACE_SOCKET_ERROR;
  }

  ptr->process_event = ndn_msgqueue_post(ptr, ndn_unix_face_recv, 0, NULL);
  if(ptr->process_event == NULL){
    ndn_face_down(self);
    return NDN_FWD_MSGQUEUE_FULL;
  }

  self->state = NDN_FACE_STATE_UP;
  return NDN_SUCCESS;
}

static int
ndn_unix_server_face_up(struct ndn_face_intf* self){
  ndn_unix_face_t* ptr = container_of(self, ndn_unix_face_t, intf);
  int ret = 0;

  if(self->state == NDN_FACE_STATE_UP){
    return NDN_SUCCESS;
  }
  ret = ndn_unix_face_up(self);
  if(ret != NDN_SUCCESS){
    return ret;
  }

  if(ptr->addr.sun_path[0] != 0){
    unlink(ptr->addr.sun_path);
  }
  if(bind(ptr->sock, (struct sockaddr*)&ptr->addr, sizeof(ptr->addr)) == -1){
    ndn_face_down(self);
    return NDN_UNIX_FACE_SOCKET_ERROR;
  }

  if(listen(ptr->sock, 0) == -1){
    ndn_face_down(self);
    return NDN_UNIX_FACE_SOCKET_ERROR;
  }

  chmod(ptr->addr.sun_path, 0666);

  ptr->process_event = ndn_msgqueue_post(ptr, ndn_unix_face_accept, 0, NULL);
  if(ptr->process_event == NULL){
    ndn_face_down(self);
    return NDN_FWD_MSGQUEUE_FULL;
  }

  self->state = NDN_FACE_STATE_UP;
  return NDN_SUCCESS;
}

static int
ndn_unix_face_down(struct ndn_face_intf* self){
  ndn_unix_face_t* ptr = (ndn_unix_face_t*)self;
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
ndn_unix_face_destroy(ndn_face_intf_t* self){
  ndn_face_down(self);
  ndn_forwarder_unregister_face(self);
  free(self);
}

static int
ndn_unix_face_send(ndn_face_intf_t* self, const uint8_t* packet, uint32_t size){
  ndn_unix_face_t* ptr = container_of(self, ndn_unix_face_t, intf);
  ssize_t ret;
  ret = send(ptr->sock, packet, size, 0);
  if(ret != size){
    //printf("ERROR: Send error %d\n", errno);
    return NDN_UNIX_FACE_SOCKET_ERROR;
  }else{
    return NDN_SUCCESS;
  }
}

ndn_unix_face_t*
ndn_unix_face_construct(const char* addr, bool client){
  ndn_unix_face_t* ret;
  int iret;

  ret = (ndn_unix_face_t*)malloc(sizeof(ndn_unix_face_t));
  if(!ret){
    return NULL;
  }

  ret->intf.face_id = NDN_INVALID_ID;
  iret = ndn_forwarder_register_face(&ret->intf);
  if(iret != NDN_SUCCESS){
    free(ret);
    return NULL;
  }

  ret->intf.type = NDN_FACE_TYPE_APP;
  ret->intf.state = NDN_FACE_STATE_DOWN;
  if(client){
    ret->intf.up = ndn_unix_client_face_up;
  }else{
    ret->intf.up = ndn_unix_server_face_up;
  }
  ret->intf.down = ndn_unix_face_down;
  ret->intf.send = ndn_unix_face_send;
  ret->intf.destroy = ndn_unix_face_destroy;

  ret->addr.sun_family = AF_UNIX;
  if (addr[0] == '\0') {
    // Hidden path
    ret->addr.sun_path[0] = '\0';
    strncpy(ret->addr.sun_path + 1, addr + 1, sizeof(ret->addr.sun_path) - 2);
  } else {
    strncpy(ret->addr.sun_path, addr, sizeof(ret->addr.sun_path) - 1);
  }

  ret->client = client;
  ret->sock = -1;
  ret->offset = 0;
  ret->process_event = NULL;
  ndn_face_up(&ret->intf);

  return ret;
}

static ndn_unix_face_t*
ndn_unix_slave_face_construct(int sock){
  ndn_unix_face_t* ret;
  int iret;

  ret = (ndn_unix_face_t*)malloc(sizeof(ndn_unix_face_t));
  if(!ret){
    return NULL;
  }

  ret->intf.face_id = NDN_INVALID_ID;
  iret = ndn_forwarder_register_face(&ret->intf);
  if(iret != NDN_SUCCESS){
    free(ret);
    return NULL;
  }
  //printf("New face registered %d\n", ret->intf.face_id);

  ret->intf.type = NDN_FACE_TYPE_APP;
  ret->intf.state = NDN_FACE_STATE_UP;
  ret->intf.up = NULL;
  ret->intf.down = ndn_unix_slave_face_down;
  ret->intf.send = ndn_unix_face_send;
  ret->intf.destroy = NULL;

  ret->client = false;
  ret->sock = sock;
  ret->offset = 0;
  ret->process_event = ndn_msgqueue_post(ret, ndn_unix_face_recv, 0, NULL);
  if(ret->process_event == NULL){
    ndn_face_down(&ret->intf);
    return NULL;
  }

  return ret;
}

static int
ndn_unix_slave_face_down(struct ndn_face_intf* self){
  ndn_unix_face_down(self);
  ndn_forwarder_unregister_face(self);
  free(container_of(self, ndn_unix_face_t, intf));
  //printf("Unix face deleted %d\n", container_of(self, ndn_unix_face_t, intf)->sock);
  return NDN_SUCCESS;
}

static void
ndn_unix_face_recv(void *self, size_t param_len, void *param){
  ndn_unix_face_t* ptr = (ndn_unix_face_t*)self;
  ssize_t size;
  uint8_t *buf, *valptr;
  uint32_t cur_type, cur_size;

  // It works without this line but I think adding is better, following the logic.
  // So ndn_face_down won't cancel a not existing event.
  ptr->process_event = NULL;

  size = recv(ptr->sock,
              ptr->buf + ptr->offset,
              sizeof(ptr->buf) - ptr->offset,
              0);
  if(size > 0){
    // Some packets recved
    size += ptr->offset;
    for(buf = ptr->buf; buf < ptr->buf + size; buf += cur_size){
      valptr = tlv_get_type_length(buf, ptr->buf + size - buf, &cur_type, &cur_size);
      if(valptr == NULL){
        break;
      }
      cur_size += valptr - buf;
      if(buf + cur_size > ptr->buf + size){
        break;
      }
      ndn_forwarder_receive(&ptr->intf, buf, cur_size);
    }
    if(buf < ptr->buf + size){
      // TODO: Too large packets will block the receive.
      memcpy(ptr->buf, buf, ptr->buf + size - buf);
      ptr->offset = ptr->buf + size - buf;
    }else{
      ptr->offset = 0;
    }
  }else if(size == -1 && errno == EWOULDBLOCK){
    // No more packet
  }else{
    // size == 0 means a shutdown
    ndn_face_down(&ptr->intf);
    return;
  }

  ptr->process_event = ndn_msgqueue_post(self, ndn_unix_face_recv, param_len, param);
}

static void
ndn_unix_face_accept(void *self, size_t param_len, void *param){
  ndn_unix_face_t* ptr = (ndn_unix_face_t*)self;
  int ret = 0;

  ptr->process_event = NULL;

  ret = accept(ptr->sock, NULL, NULL);
  if(ret >= 0){
    //printf("New face created %d\n", ret);
    if(ndn_unix_slave_face_construct(ret) == NULL){
      close(ret);
    }
  }else if(ret == -1 && errno == EWOULDBLOCK){
    //No more connections
  }else{
    ndn_face_down(&ptr->intf);
    return;
  }

  ptr->process_event = ndn_msgqueue_post(self, ndn_unix_face_accept, param_len, param);
}
