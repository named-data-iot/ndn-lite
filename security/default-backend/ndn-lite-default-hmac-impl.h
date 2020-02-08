/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_LITE_DEFAULT_HMAC_IMPL_H
#define NDN_LITE_DEFAULT_HMAC_IMPL_H

#include "sec-lib/tinycrypt/tc_hmac.h"
#include "../../ndn-constants.h"
#include <stddef.h>
#include <stdint.h>

struct abstract_hmac_key {
  /**
   * The key bytes buffer of current key.
   */
  uint8_t key_value[NDN_SEC_HMAC_MAX_KEY_SIZE];
  /**
   * The key size of key bytes.
   */
  uint32_t key_size;
};

struct abstract_hmac_sha256_state {
  struct tc_hmac_state_struct s;
};

void
ndn_lite_default_hmac_load_backend(void);

#endif // NDN_LITE_DEFAULT_HMAC_IMPL_H
