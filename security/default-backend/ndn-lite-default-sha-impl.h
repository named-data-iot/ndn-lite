/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_LITE_DEFAULT_SHA256_IMPL_H
#define NDN_LITE_DEFAULT_SHA256_IMPL_H

#include "sec-lib/tinycrypt/tc_sha256.h"

struct abstract_sha256_state {
  struct tc_sha256_state_struct s;
};

void
ndn_lite_default_sha_load_backend(void);

#endif // NDN_LITE_DEFAULT_SHA256_IMPL_H
