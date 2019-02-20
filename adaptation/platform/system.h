/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "inttypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This method initialize the platform.
 */
void ndn_platform_init(void);

/**
 * This method de-initialize the platform.
 */
void ndn_platform_deinit(void);

/**
 * This method delay the platform in millisecond, like no op.
 * @param delay. Time to delay in millisecond.
 */
void ndn_platform_delay_ms(uint32_t delay);

/**
 * This static method returns the current time in milliseconds.
 * @return The current time in milliseconds.
 */
uint64_t ndn_platform_current_time(void);


#ifdef __cplusplus
} // end of extern "C"
#endif
