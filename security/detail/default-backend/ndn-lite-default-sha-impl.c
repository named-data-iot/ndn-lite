/*
 * Copyright (C) 2018 Edward Lu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-lite-sha256-tinycrypt-impl.h"
#include "../../../../ndn-error-code.h"
#include "sec-lib/tinycrypt/tc_sha256.h"
#include "sec-lib/tinycrypt/tc_constants.h"

int
ndn_lite_default_sha256(const uint8_t* data, size_t datalen, uint8_t* hash_result)
{
  struct tc_sha256_state_struct s;
  if (tc_sha256_init(&s) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_sha256_update(&s, data, datalen) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_sha256_final(hash_result, &s) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return NDN_SUCCESS;
}
