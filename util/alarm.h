/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
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
 * @note RESERVED, should only be called internally.
 */
void ndn_alarm_millis_stop(void);

/**
 * This method will block the program until delay completion. The delay time is
 * connted by millisecond. Time counting is still running since it's driven by
 * hardware.
 * @param delay. Input. Time to delay in millisecond.
 */
void ndn_alarm_delay(uint32_t delay);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NDN_LITE_ALARM_H
