/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-lite-default-sha-impl.h"
#include "../../ndn-error-code.h"
#include "../ndn-lite-sha.h"
#include "sec-lib/tinycrypt/tc_constants.h"

int
ndn_lite_default_sha256_init(struct abstract_sha256_state* state)
{
  if (tc_sha256_init(&state->s) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  return NDN_SUCCESS;
}

int
ndn_lite_default_sha256_update(struct abstract_sha256_state* state, const uint8_t* data, uint32_t datalen)
{
  if (tc_sha256_update(&state->s, data, datalen) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  return NDN_SUCCESS;
}

int
ndn_lite_default_sha256_finish(struct abstract_sha256_state* state, uint8_t* hash_result)
{
  if (tc_sha256_final(hash_result, &state->s) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return NDN_SUCCESS;
}

void
ndn_lite_default_sha_load_backend(void)
{
  ndn_sha_backend_t* backend = ndn_sha_get_backend();
  backend->sha256_init = ndn_lite_default_sha256_init;
  backend->sha256_update = ndn_lite_default_sha256_update;
  backend->sha256_finish = ndn_lite_default_sha256_finish;
}
