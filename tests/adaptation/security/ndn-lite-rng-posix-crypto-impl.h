/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef RNG_POSIX_CRYPTO_IMPL_H
#define RNG_POSIX_CRYPTO_IMPL_H

#include <stdint.h>

/**
 * return 1 if runs successfully
 */
int
ndn_lite_posix_rng(uint8_t *dest, unsigned size);

void
ndn_lite_posix_rng_load_backend(void);

#endif // RNG_POSIX_CRYPTO_IMPL_H