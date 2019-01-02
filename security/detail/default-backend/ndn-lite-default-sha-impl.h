/*
 * Copyright (C) 2018 Edward Lu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NDN_LITE_DEFAULT_SHA256_IMPL_H
#define NDN_LITE_DEFAULT_SHA256_IMPL_H

#include <stddef.h>
#include <stdint.h>

int
ndn_lite_default_sha256(const uint8_t* data, size_t datalen, uint8_t* hash_result);

#endif // NDN_LITE_DEFAULT_SHA256_IMPL_H
