/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_RNG_TINYCRIPT_IMPL_H
#define NDN_LITE_RNG_TINYCRIPT_IMPL_H

#include <stdint.h>

int
ndn_lite_random_hkdf_tinycrypt(const uint8_t* input_value, uint32_t input_size,
                               uint8_t* output_value, uint32_t output_size,
                               const uint8_t* seed_value, uint32_t seed_size);

int
ndn_lite_random_hmacprng_tinycrypt(const uint8_t* input_value, uint32_t input_size,
                                   uint8_t* output_value, uint32_t output_size,
                                   const uint8_t* seed_value, uint32_t seed_size,
                                   const uint8_t* additional_value, uint32_t additional_size);

#endif // NDN_LITE_RNG_TINYCRIPT_IMPL_H
