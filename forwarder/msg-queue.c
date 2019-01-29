/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
 
#include "msg-queue.h"
#include <string.h>

typedef struct ndn_msg{
    void* obj;
    ndn_msg_callback func;
    size_t length;
    uint8_t param[0];
} ndn_msg_t;

static uint8_t msg_queue[NDN_MSGQUEUE_SIZE];
static ndn_msg_t *pfront, *ptail;

#define MSGQUEUE_NEXT(ptr) \
  ptr = (ndn_msg_t*)(((uint8_t*)ptr) + ptr->length); \
  if(((uint8_t*)ptr) >= &msg_queue[NDN_MSGQUEUE_SIZE]){ \
    ptr = (ndn_msg_t*)&msg_queue[0]; \
  };


void
ndn_msgqueue_init(void) {
  pfront = ptail = (ndn_msg_t*)&msg_queue;
}

bool
ndn_msgqueue_empty(void) {
  if(pfront->func == NDN_MSG_PADDING && pfront != ptail){
    pfront = (ndn_msg_t*)&msg_queue;
  }
  if(pfront == ptail){
    // defrag when empty
    pfront = ptail = (ndn_msg_t*)&msg_queue[0];
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

bool
ndn_msgqueue_post(void *target,
                  ndn_msg_callback reason,
                  size_t param_length,
                  void *param)
{
  size_t len = param_length + sizeof(ndn_msg_t);
  size_t space;

  // defrag the memory
  ndn_msgqueue_empty();
  
  if(pfront > ptail) {
    // -1 is to prevent (ptail == pfront) after call
    space = ((uint8_t*)pfront) - ((uint8_t*)ptail) - 1;
  } else {
    space = (&msg_queue[NDN_MSGQUEUE_SIZE] - ((uint8_t*)ptail));
  }
  
  // After tail?
  if(pfront >= ptail || space >= len){
    // No-padding (= is to prevent ptail == pfront after call)
    if(space < len || (space == len && pfront == (ndn_msg_t*)&msg_queue))
      return false;
  } else {
    // Padding & rewind (= is to prevent ptail == pfront after call)
    if(((uint8_t*)pfront) - &msg_queue[0] <= len)
      return false;
    
    ptail->func = NDN_MSG_PADDING;
    ptail->length = space;
    
    ptail = (ndn_msg_t*)&msg_queue[0];
  }
  
  ptail->obj = target;
  ptail->func = reason;
  ptail->length = len;
  memcpy(ptail->param, param, param_length);
  MSGQUEUE_NEXT(ptail);
  
  return true;
}
