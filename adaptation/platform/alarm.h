/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void ndn_platform_alarm_millis_start(uint32_t start, uint32_t delta);

uint32_t ndn_platform_alarm_millis_get_now(void);

// reserved, should only be a system call
void ndn_platform_alarm_millis_stop(void);

void ndn_platform_alarm_process(void* instance);


// defined in timer.c
extern void ndn_platform_alarm_millis_fire(void* instance);

extern void ndn_platform_alarm_micros_fire(void* instance);

#ifdef __cplusplus
} // extern "C"
#endif
