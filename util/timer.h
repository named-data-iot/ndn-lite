/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_TIMER_H
#define NDN_LITE_TIMER_H

#include <stdbool.h>
#include "../ndn-constants.h"
#include "../ndn-error-code.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * handler is a function pointer to the timer callback.
 * After invoking the function, the caller will process the timeout.
 * @param arg. Input. The incoming argument.
 */
typedef int (*handler)(const uint8_t* block_value, uint32_t block_size);

/**
 * The structure to represent a timer.
 */
typedef struct ndn_timer {
  /**
   * Timer timeout callback handler.
   */
  handler handler;
  /**
   * Delta between start time and expiry time.
   */
  uint64_t fire_time;
  /**
   * Input argument for timer handler
   */
  void* block_value;

  uint32_t block_size;
} ndn_timer_t;

static inline void
ndn_timer_reset(ndn_timer_t* timer)
{
  timer->handler = NULL;
  timer->fire_time = NDN_TIMER_INVALID_FIRETIME;
  timer->block_value = NULL;
  timer->block_size = 0;
}

/**
 * This method initialize a timer structure.
 * @param timer. Input. Timer to init.
 * @param timeout. Input. Timeout handler.
 * @param arg. Input. Argument to put into timeout handler.
 */
static inline void
ndn_timer_init(ndn_timer_t* timer, handler timeout, uint32_t fire_time,
               void* block_value, uint32_t block_size)
{
  timer->handler = timeout;
  timer->fire_time = fire_time;
  timer->block_value = block_value;
  timer->block_size = block_size;
}

/**
 * This method will invoke a timer's handler.
 * @param timer. Input. Timer to fire.
 */
static inline void
ndn_timer_fire(ndn_timer_t* timer) {
  timer->handler(timer->block_value, timer->block_size);

  //reset timer
  ndn_timer_reset(timer);
}

#ifdef __cplusplus
}
#endif
#endif /* NDN_TIMER_H */
/** @} */
