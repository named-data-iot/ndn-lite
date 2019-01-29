/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_MSG_QUEUE_H_
#define FORWARDER_MSG_QUEUE_H_

#include <inttypes.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The size of message queue in bytes.
 */
#define NDN_MSGQUEUE_SIZE 4096

#define NDN_MSG_PADDING (void*)(-1)

typedef void(*ndn_msg_callback)(void *self,
                                size_t param_length,
                                void *param);

void
ndn_msgqueue_init(void);

bool
ndn_msgqueue_post(void *target,
                  ndn_msg_callback reason,
                  size_t param_length,
                  void *param);
  
bool
ndn_msgqueue_dispatch(void);

bool
ndn_msgqueue_empty(void);

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_MSG_QUEUE_H_
