/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-lite-sha.h"
#include "ndn-lite-sec-config.h"
#include "ndn-lite-sec-utils.h"

ndn_sha_backend_t ndn_sha_backend;

ndn_sha_backend_t*
ndn_sha_get_backend(void)
{
  return &ndn_sha_backend;
}

int
ndn_sha256_init(ndn_sha256_state_t* state)
{
  return ndn_sha_backend.sha256_init(&state->abs_state);
}

int
ndn_sha256_update(ndn_sha256_state_t* state, const uint8_t* data, uint32_t datalen)
{
  return ndn_sha_backend.sha256_update(&state->abs_state, data, datalen);
}

int
ndn_sha256_finish(ndn_sha256_state_t* state, uint8_t* hash_result)
{
  return ndn_sha_backend.sha256_finish(&state->abs_state, hash_result);
}

int
ndn_sha256(const uint8_t* data, uint32_t datalen, uint8_t* hash_result)
{
  ndn_sha256_state_t state;
  if (ndn_sha256_init(&state) != NDN_SUCCESS)
    return NDN_SEC_INIT_FAILURE;
  if (ndn_sha256_update(&state, data, datalen) != NDN_SUCCESS)
    return NDN_SEC_INIT_FAILURE;
  if (ndn_sha256_finish(&state, hash_result) != NDN_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  return NDN_SUCCESS;
}

int
ndn_sha256_sign(const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_max_size,
                uint32_t* output_used_size)
{
  if (output_max_size < NDN_SEC_SHA256_HASH_SIZE)
    return NDN_OVERSIZE;
  if (ndn_sha256(input_value, input_size, output_value) != NDN_SUCCESS) {
    return NDN_SEC_SHA256_HASH_SIZE;
  }
  *output_used_size = NDN_SEC_SHA256_HASH_SIZE;
  return NDN_SUCCESS;
}

int
ndn_sha256_verify(const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* sig_value, uint32_t sig_size)
{
  if (sig_size != NDN_SEC_SHA256_HASH_SIZE)
    return NDN_SEC_WRONG_SIG_SIZE;
  uint8_t input_hash[NDN_SEC_SHA256_HASH_SIZE] = {0};
  ndn_sha256(input_value, input_size, input_hash);
  if (ndn_const_time_memcmp(input_hash, sig_value, sizeof(input_hash)) != 0)
    return NDN_SEC_FAIL_VERIFY_SIG;
  else
    return NDN_SUCCESS;
}
