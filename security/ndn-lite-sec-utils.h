/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_UTILS_H_
#define NDN_SECURITY_UTILS_H_

#include <inttypes.h>

int
ndn_const_time_memcmp(const uint8_t* a, const uint8_t* b, uint32_t size);

#endif // NDN_SECURITY_UTILS_H_
