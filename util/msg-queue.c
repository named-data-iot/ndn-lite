/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "msg-queue.h"
#include <string.h>

/** Padding message
 *
 * This will only occur at the end of the queue.
 * When the last message's @c func is NDN_MSG_PADDING, it means the next message is at
 * the begining of the queue and has a size larger than this padding one.
 */
#define NDN_MSG_PADDING (ndn_msg_callback)(-1)

#pragma pack(1)
typedef struct ndn_msg{
  void* obj;
  ndn_msg_callback func;
  size_t length;
  uint8_t param[];
} ndn_msg_t;
#pragma pack()

static uint8_t msg_queue[NDN_MSGQUEUE_SIZE];
static ndn_msg_t *pfront, *ptail, *psplit;

#define MSGQUEUE_NEXT(ptr) \
  ptr = (ndn_msg_t*)(((uint8_t*)ptr) + ptr->length); \
  if(((uint8_t*)ptr) >= &msg_queue[NDN_MSGQUEUE_SIZE]){ \
    ptr = (ndn_msg_t*)&msg_queue[0]; \
  };


void
ndn_msgqueue_init(void) {
  pfront = ptail = psplit = (ndn_msg_t*)&msg_queue;
}

bool
ndn_msgqueue_empty(void) {
  while(pfront->func == NDN_MSG_PADDING && pfront != ptail){
    MSGQUEUE_NEXT(pfront);
  }
  if(pfront == ptail){
    // defrag when empty
    pfront = ptail = psplit = (ndn_msg_t*)&msg_queue[0];
    return true;
  } else
    return false;
}

bool
ndn_msgqueue_dispatch(void) {
  if(ndn_msgqueue_empty())
    return false;

  pfront->func(pfront->obj, pfront->length - sizeof(ndn_msg_t), pfront->param);
  MSGQUEUE_NEXT(pfront);
  return true;
}

struct ndn_msg*
ndn_msgqueue_post(void *target,
                  ndn_msg_callback reason,
                  size_t param_length,
                  void *param)
{
  size_t len = param_length + sizeof(ndn_msg_t);
  size_t space;
  ndn_msg_t* ret;

  // defrag the memory
  ndn_msgqueue_empty();

  if(pfront > ptail) {
    // -1 is to prevent (ptail == pfront) after call
    space = ((uint8_t*)pfront) - ((uint8_t*)ptail) - 1;
  } else {
    space = (&msg_queue[NDN_MSGQUEUE_SIZE] - ((uint8_t*)ptail));
  }

  // After tail?
  if(pfront >= ptail || space >= len + sizeof(ndn_msg_t)){
    // No-padding (= is to prevent ptail == pfront after call)
    if(space < len || (space == len && pfront == (ndn_msg_t*)&msg_queue))
      return NULL;
  } else {
    // Padding & rewind (= is to prevent ptail == pfront after call)
    if(((uint8_t*)pfront) - &msg_queue[0] <= (int) len)
      return NULL;

    if(space >= sizeof(ndn_msg_t)){
      ptail->func = NDN_MSG_PADDING;
      ptail->length = space;
      ptail = (ndn_msg_t*)&msg_queue[0];
    }else{
      // This should never happen
      return NULL;
    }
  }

  ptail->obj = target;
  ptail->func = reason;
  ptail->length = len;
  if(param_length > 0){
    memcpy(ptail->param, param, param_length);
  }

  ret = ptail;
  MSGQUEUE_NEXT(ptail);

  return ret;
}

void
ndn_msgqueue_process(void) {
  psplit = ptail;
  while(pfront != psplit){
    ndn_msgqueue_dispatch();
  }
}

void
ndn_msgqueue_cancel(struct ndn_msg* msg){
  msg->func = NDN_MSG_PADDING;
}
