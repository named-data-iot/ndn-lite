/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef UTIL_UNIFORM_TIME_H
#define UTIL_UNIFORM_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**@defgroup NDNUtil
 */

/** @defgroup NDNUtilUniTime Time Function
 * @ingroup NDNUtil
 *
 * Unified interfaces to get time, since different platform has different implementations.
 * @{
 */

/** Time count in milli-seconds */
typedef uint64_t ndn_time_ms_t;

/** Time count in micro-seconds */
typedef uint64_t ndn_time_us_t;

/** Get current time count in ms.
 * @return Time count. The absolute value is meaningless.
 */
ndn_time_ms_t ndn_time_now_ms(void);

/** Get current time count in us
 * @return Time count. The absolute value is meaningless.
 */
ndn_time_us_t ndn_time_now_us(void);

/** Sleep for a specified time interval.
 * @param[in] delay Time to delay in ms.
 */
void ndn_time_delay(ndn_time_ms_t delay);

/*@}*/

#ifdef __cplusplus
} // extern "C"
#endif

#endif // UTIL_UNIFORM_TIME_H
