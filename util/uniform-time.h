/*
 * Copyright (C) 2019 Tianyuan Yu, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef UTIL_UNIFORM_TIME_H
#define UTIL_UNIFORM_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t ndn_time_ms_t;
typedef uint64_t ndn_time_us_t;

ndn_time_ms_t ndn_time_now_ms(void);
ndn_time_us_t ndn_time_now_us(void);
void ndn_time_delay(ndn_time_ms_t delay);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // UTIL_UNIFORM_TIME_H
