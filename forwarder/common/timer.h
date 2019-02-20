/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef TIMER_H
#define TIMER_H

#include "../../adaptation/platform/alarm.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*handler)(void* arg);

typedef struct ndn_timer {
  handler handler;
  uint32_t fire_time;
  void* arg;

  struct ndn_timer* next;
} ndn_timer_t;

typedef struct ndn_alarm_api {
  void (*alarm_start)(uint32_t start, uint32_t expire);
  void (*alarm_stop)(void);
  uint32_t (*alarm_get_now)(void);
} ndn_alarm_api_t;

typedef struct ndn_timer_scheduler {
  ndn_timer_t* head;
  ndn_alarm_api_t api;
} ndn_timer_scheduler_t;

static inline void
ndn_timer_init(ndn_timer_t* timer, handler timeout, uint32_t fire_time, void* arg) {
  timer->next = timer;
  timer->handler = timeout;
  timer->fire_time = fire_time;
  timer->arg = arg;
}

static inline void
ndn_timer_fire(ndn_timer_t* timer) {
  timer->handler(timer->arg);
}

/**
 * This method indicates whether or not the timer instance is running.
 *
 * @retval TRUE   If the timer is running.
 * @retval FALSE  If the timer is not running.
 *
 */
static inline bool
ndn_timer_is_running(ndn_timer_t* timer) {
  return (timer->next != timer);
}

/**
 * This method indicates if the fire time of this timer is strictly before the fire time of a second given timer.
 *
 * @param[in]  aTimer   A reference to the second timer object.
 * @param[in]  aNow     The current time (may in milliseconds or microsecond, which depends on the timer type).
 *
 * @retval TRUE  If the fire time of this timer object is strictly before aTimer's fire time
 * @retval FALSE If the fire time of this timer object is the same or after aTimer's fire time.
 *
 */
bool
ndn_timer_fire_before(ndn_timer_t* lhs, ndn_timer_t* rhs, uint32_t now);

/**
 * This static method returns the current time in milliseconds.
 *
 * @returns The current time in milliseconds.
 *
 */
static inline uint32_t
ndn_timer_get_now(void) {
  return ndn_platform_alarm_millis_get_now(); 
}

void
ndn_timer_stop(ndn_timer_t* timer);

void
ndn_timer_start(ndn_timer_t* timer, uint32_t start, uint32_t expire);

static inline void
ndn_timer_start_now(ndn_timer_t* timer, uint32_t expire) {
  ndn_timer_start(timer, ndn_timer_get_now(), expire);
}

// this must be called at the very beginning, to set up APIs
void
ndn_timer_scheduler_init(ndn_timer_scheduler_t* scheduler);

/**
 * This method removes a timer instance to the timer scheduler.
 *
 * @param[in]  aTimer     A reference to the timer instance.
 * @param[in]  aAlarmApi  A reference to the Alarm APIs.
 *
 */
void
ndn_timer_scheduler_add(ndn_timer_scheduler_t* scheduler, ndn_timer_t* timer);

void
ndn_timer_scheduler_remove(ndn_timer_scheduler_t* scheduler, ndn_timer_t* timer);

/**
 * This method processes the running timers.
 *
 * @param[in]  aAlarmApi  A reference to the Alarm APIs.
 *
 */
void
ndn_timer_scheduler_process(ndn_timer_scheduler_t* scheduler);

/**
 * This method sets the platform alarm based on timer at front of the list.
 *
 * @param[in]  aAlarmApi  A reference to the Alarm APIs.
 *
 */
void
ndn_timer_scheduler_set_alarm(ndn_timer_scheduler_t* scheduler);


ndn_timer_scheduler_t*
ndn_timer_scheduler_get_instance(void);


#ifdef __cplusplus
}
#endif
#endif /* TIMER_H */
/** @} */