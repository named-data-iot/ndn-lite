/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_CRYPTO_KEY_H
#define NDN_SECURITY_CRYPTO_KEY_H

#include "../encode/name.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The opaque abstract_key struct to be implemented by the backend.
 */
typedef struct abstract_key abstract_key_t;

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_CRYPTO_KEY_H
