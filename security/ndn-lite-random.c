/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-sec-config.h"

#include "ndn-lite-random.h"
#include "ndn-lite-sign-verify.h"
#include "detail/detail-rng/ndn-lite-rng-tinycrypt-impl.h"

int
ndn_random_hkdf(const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_size,
                const uint8_t* seed_value, uint32_t seed_size)
{
  #ifdef NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
  return ndn_lite_random_hkdf_tinycrypt(input_value, input_size,
                                        output_value, output_size,
                                        seed_value, seed_size);
  #endif
}

int
ndn_random_hmacprng(const uint8_t* input_value, uint32_t input_size,
                    uint8_t* output_value, uint32_t output_size,
                    const uint8_t* seed_value, uint32_t seed_size,
                    const uint8_t* additional_value, uint32_t additional_size)
{
  #ifdef NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT
  return ndn_lite_random_hmacprng_tinycrypt(input_value, input_size,
                                            output_value, output_size,
                                            seed_value, seed_size,
                                            additional_value, additional_size);
  #endif
}