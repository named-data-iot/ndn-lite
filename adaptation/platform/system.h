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

void ndn_platform_init(void);

void ndn_platform_deinit(void);

void ndn_platform_delay_ms(uint32_t delay);

uint32_t ndn_platform_current_time(void);


#ifdef __cplusplus
} // end of extern "C"
#endif

