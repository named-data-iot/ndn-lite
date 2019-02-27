/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <inttypes.h>
#include <string.h>

#include "ndn-lite-timer.h"
#include "nnd-lite-alarm.h"

static ndn_alarm_api_t api = {
  &ndn_alarm_millis_start,
  &ndn_alarm_millis_stop,
  &ndn_alarm_millis_get_now
};

static ndn_timer_scheduler_t scheduler;

void
ndn_timer_start(ndn_timer_t* timer, uint32_t start, uint32_t expire)
{
  timer->fire_time = start + expire;
  ndn_timer_scheduler_add(&scheduler, timer);
}

void
ndn_timer_stop(ndn_timer_t* timer)
{
  ndn_timer_scheduler_remove(&scheduler, timer);
}

bool
ndn_timer_fire_before(ndn_timer_t* lhs, ndn_timer_t* rhs, uint32_t now)
{
  bool retval;
  bool lhs_is_before_now = lhs->fire_time < now ? true : false;
  bool rhs_is_before_now = rhs->fire_time < now ? true : false;
    // Check if one timer is before `now` and the other one is not.
    if (lhs_is_before_now != rhs_is_before_now){
        // One timer is before `now` and the other one is not, so if this timer's fire time is before `now` then
        // the second fire time would be after `now` and this timer would fire before the second timer.
        return lhs_is_before_now;
    }
    else{
        // Both timers are before `now` or both are after `now`. Either way the difference is guaranteed to be less
        // than `kMaxDt` so we can safely compare the fire times directly.
        return lhs->fire_time < rhs->fire_time ? true : false;
    }
}

void
ndn_timer_scheduler_init(ndn_timer_scheduler_t* scheduler) {
  scheduler->head = NULL;
  scheduler->api = api;
}

void
ndn_timer_scheduler_add(ndn_timer_scheduler_t* scheduler, ndn_timer_t* timer)
{
  ndn_timer_scheduler_remove(scheduler, timer); // if same timer appear again, should remove the old one first

  if (scheduler->head == NULL){
    scheduler->head = timer;
    timer->next = NULL;
    ndn_timer_scheduler_set_alarm(scheduler);
  }
  else{
    ndn_timer_t* prev = NULL;
    ndn_timer_t* cur;
    for (cur = scheduler->head; cur; cur = cur->next){
      if (ndn_timer_fire_before(timer, cur, api.alarm_get_now())){
        if (prev){
          timer->next = cur;
          prev->next = timer;
        }
        else{
          timer->next = scheduler->head;
          scheduler->head = timer;
          ndn_timer_scheduler_set_alarm(scheduler);
        }

        break;
      }

      prev = cur;
    }

    if (cur == NULL){
      prev->next = timer;
      timer->next = NULL;
    }
  }
}

void
ndn_timer_scheduler_remove(ndn_timer_scheduler_t* scheduler, ndn_timer_t* timer)
{
  if (timer->next == timer) // a not in-queue timer
    return;

  if (scheduler->head == timer){
    scheduler->head = timer->next;
    ndn_timer_scheduler_set_alarm(scheduler);
  }
  else{
    for (ndn_timer_t *cur = scheduler->head; cur; cur = cur->next){
      if (cur->next == timer){
        cur->next = timer->next;
        break;
      }
    }
  }

  timer->next = timer;
}

/**
 * This method processes the running timers.
 *
 * @param[in]  aAlarmApi  A reference to the Alarm APIs.
 *
 */
void
ndn_timer_scheduler_process(ndn_timer_scheduler_t* scheduler)
{
  ndn_timer_t* timer = scheduler->head;
  if (timer){
    if (api.alarm_get_now() < timer->fire_time? false : true){
      ndn_timer_scheduler_remove(scheduler, timer);
      ndn_timer_fire(timer);
    }
    else{
      ndn_timer_scheduler_set_alarm(scheduler);
    }
  }
  else{
    ndn_timer_scheduler_set_alarm(scheduler);
  }
}

/**
 * This method sets the platform alarm based on timer at front of the list.
 *
 * @param[in]  aAlarmApi  A reference to the Alarm APIs.
 *
 */
void
ndn_timer_scheduler_set_alarm(ndn_timer_scheduler_t* scheduler)
{
  if (scheduler->head == NULL){
    api.alarm_stop();
  }
  else{
    uint32_t now = api.alarm_get_now();
    uint32_t remaining = now < scheduler->head->fire_time?
                         (scheduler->head->fire_time - now) : 0;
    api.alarm_start(now, remaining);
  }
}

ndn_timer_scheduler_t*
ndn_timer_scheduler_get_instance(void)
{
  return &scheduler;
}

extern void
ndn_platform_alarm_millis_fire(void* scheduler) {
  ndn_timer_scheduler_process((ndn_timer_scheduler_t*)scheduler);
  return;
}
