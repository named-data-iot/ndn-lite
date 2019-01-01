/*
 * Copyright (C) 2018 Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NDN_LITE_SHA256_TINYCRIPT_IMPL_H
#define NDN_LITE_SHA256_TINYCRIPT_IMPL_H

#include <stddef.h>
#include <stdint.h>

int
ndn_lite_sha256_tinycrypt(const uint8_t* data, size_t datalen, uint8_t* hash_result);

#endif // NDN_LITE_SHA256_TINYCRIPT_IMPL_H
