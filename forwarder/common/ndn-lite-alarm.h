/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_ALARM_H
#define NDN_LITE_ALARM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Alarm is basic component to implement in-library timers, and low-end APIs must
 * come from either Operating Systerms or SDKs, which are out of NDN Lite' scope.
 * This header file defines the interfaces of Alarm, its implementation locates in
 * platform specific adaptation module.
 */

/**
 * This method will init alarm.
 */
void ndn_alarm_init(void);

/**
 * This method will de-init alarm.
 */
void ndn_alarm_deinit(void);

/**
 * This method will start alarm.
 * @param start. Input. Timer start time.
 * @param delta. Input. Delta between timer start time and expiry time.
 */
void ndn_alarm_millis_start(uint32_t start, uint32_t delta);

/**
 * This method will get current system time (in millisecond) from alarm.
 * @return Current time
 */
uint64_t ndn_alarm_millis_get_now(void);

/**
 * This method will get current system time (in microsecond) from alarm.
 * @return Current time
 */
uint64_t ndn_alarm_micros_get_now(void);

/**
 * This method will stop alarm.
 * @note reserved, should only be called internally.
 */
void ndn_alarm_millis_stop(void);

/**
 * This method will process alarm.
 * @param instance. Input. Timer scheduler instance.
 */
void ndn_alarm_process(void* instance);

/**
 * This method will fire millisecond alarm.
 * @param instance. Input. Timer scheduler instance.
 */
extern void ndn_alarm_millis_fire(void* instance);

/**
 * This method will fire microsecond alarm.
 * @note NOT SUPPORTED YET.
 * @param instance. Input. Timer scheduler instance.
 */
extern void ndn_alarm_micros_fire(void* instance);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NDN_LITE_ALARM_H
