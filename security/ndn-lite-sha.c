/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-sha.h"
#include "ndn-lite-sec-config.h"
#include "ndn-lite-sec-utils.h"

int
sha256(const uint8_t* data, uint32_t datalen, uint8_t* hash_result)
{
#ifdef NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
  return ndn_lite_default_sha256(data, datalen, hash_result);
#endif
}

int
ndn_sha256_sign(const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_max_size,
                uint32_t* output_used_size)
{
  if (output_max_size < NDN_SEC_SHA256_HASH_SIZE)
    return NDN_OVERSIZE;
  if (sha256(input_value, input_size, output_value) != NDN_SUCCESS) {
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
  sha256(input_value, input_size, input_hash);
  if (ndn_const_time_memcmp(input_hash, sig_value, sizeof(input_hash)) != 0)
    return NDN_SEC_FAIL_VERIFY_SIG;
  else
    return NDN_SUCCESS;
}
