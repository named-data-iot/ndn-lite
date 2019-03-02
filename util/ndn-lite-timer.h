/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_TIMER_H
#define NDN_LITE_TIMER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * handler is a function pointer to the timer callback.
 * After invoking the function, the caller will process the timeout.
 * @param arg. Input. The incoming argument.
 */
typedef void (*handler)(void* arg);

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
  void* arg;
  /**
   * Pointer to the next timer, should point to the timer itself when init.
   */
  struct ndn_timer* next;
} ndn_timer_t;

/**
 * The structure to represent alarm APIs provided by specific platform backend.
 * @note APIs may change, and only support millisecond precision by now.
 */
typedef struct ndn_alarm_api {
  /**
   * Alarm start API.
   * @param start. Input. Timer start time.
   * @param delta. Input. Delta between timer start time and expiry time.
   */
  void (*alarm_start)(uint32_t start, uint32_t delta);
  /**
   * Alarm stop API.
   */
  void (*alarm_stop)(void);
  /**
   * Alarm get current time API.
   */
  uint32_t (*alarm_get_now)(void);
} ndn_alarm_api_t;

/**
 * The structure to represent a timer scheduler in front end.
 */
typedef struct ndn_timer_scheduler {
  /**
   * Pointer to the current timer list head.
   */
  ndn_timer_t* head;
   /**
   * Used backend platform APIs.
   */
  ndn_alarm_api_t api;
} ndn_timer_scheduler_t;

/**
 * This method initialize a timer structure.
 * @param timer. Input. Timer to init.
 * @param timeout. Input. Timeout handler.
 * @param arg. Input. Argument to put into timeout handler.
 */
static inline void
ndn_timer_init(ndn_timer_t* timer, handler timeout, uint32_t fire_time, void* arg) {
  timer->next = timer;
  timer->handler = timeout;
  timer->fire_time = fire_time;
  timer->arg = arg;
}

/**
 * This method will invoke a timer's handler.
 * @param timer. Input. Timer to fire.
 */
static inline void
ndn_timer_fire(ndn_timer_t* timer) {
  timer->handler(timer->arg);
}

/**
 * This method indicates whether or not the timer instance is running.
 * @return TRUE   If the timer is running.
 * @return FALSE  If the timer is not running.
 */
static inline bool
ndn_timer_is_running(ndn_timer_t* timer) {
  return (timer->next != timer);
}

/**
 * This method indicates if the fire time of lhs timer is strictly before the fire time of the rhs timer.
 * @param lhs. Input. Left-hand-side timer.
 * @param rhs. Input. Right-hand-side timer.
 * @param now. Input. The current time (may in milliseconds or microsecond).
 * @return TRUE  If the fire time of lhs timer is strictly before rhs timer's fire time
 * @return FALSE If the fire time of lhs timer is the same or after rhs timer's fire time.
 */
bool
ndn_timer_fire_before(ndn_timer_t* lhs, ndn_timer_t* rhs, uint64_t now);

/**
 * This method will stop a running timer.
 */
void
ndn_timer_stop(ndn_timer_t* timer);

/**
 * This method will start a timer.
 * @param timer. Input. Timer to start.
 * @param start. Input. Timer start time.
 * @param delta. Input. Delta between timer start time and expiry time.
 */
void
ndn_timer_start(ndn_timer_t* timer, uint64_t start, uint32_t delta);

/**
 * This method will start a timer from now.
 * @param timer. Input. Timer to start.
 * @param delta. Input. Delta between now and expiry time.
 */
static inline void
ndn_timer_start_now(ndn_timer_t* timer, uint32_t delta) {
  ndn_timer_start(timer, ndn_timer_get_now(), delta);
}


/**
 * This method initialize a timer scheduler structure.
 * @note This method should be called before timers start, to set up APIs.
 * @param scheduler. Input. Timer scheduler to init.
 */
void
ndn_timer_scheduler_init(ndn_timer_scheduler_t* scheduler);

/**
 * This method adds a timer instance to the timer scheduler.
 * @param scheduler. Input. Timer scheduler to add timer to.
 * @param timer. Input. Timer to add.
 */
void
ndn_timer_scheduler_add(ndn_timer_scheduler_t* scheduler, ndn_timer_t* timer);

/**
 * This method removes a timer instance from the timer scheduler.
 * @param scheduler. Input. Timer scheduler to remove timer from.
 * @param timer. Input. Timer to remove.
 */
void
ndn_timer_scheduler_remove(ndn_timer_scheduler_t* scheduler, ndn_timer_t* timer);

/**
 * This method processes the running timers.
 * @param scheduler. Input. Timer scheduler which holds the timer list.
 */
void
ndn_timer_scheduler_process(ndn_timer_scheduler_t* scheduler);

/**
 * This method sets the platform alarm based on timer at front of the list.
 * @param scheduler. Input. Timer scheduler which holds the timer list.
 */
void
ndn_timer_scheduler_set_alarm(ndn_timer_scheduler_t* scheduler);

/**
 * Get a running instance of timer scheduler.
 * @return the pointer to the timer scheduler instance.
 */
ndn_timer_scheduler_t*
ndn_timer_scheduler_get_instance(void);


#ifdef __cplusplus
}
#endif
#endif /* NDN_LITE_TIMER_H */
/** @} */
