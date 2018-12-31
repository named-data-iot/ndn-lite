/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_RANDOM_H_
#define NDN_SECURITY_RANDOM_H_

#include "../encode/name.h"

#ifdef __cplusplus
extern "C" {
#endif

// @param input_value -- random input that requires KDF
// @param input_size -- random input length in bytes
// @param output_value -- buffer to receive output
// @param output_size -- size of the output buffer
// @param seed_value -- entropy to mix into the prng
// @param seed_size -- entropy length in bytes
int
ndn_random_hkdf(const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_size,
                const uint8_t* seed_value, uint32_t seed_size);

// @param input_value -- personalization string
// @param input_size -- personalization length in bytes
// @param output_value -- buffer to receive output
// @param output_size -- size of the output buffer
// @param seed_value -- entropy to mix into the prng, highly recommended larger than 32 bytes
// @param seed_size -- entropy length in bytes, highly recommended larger than 32 bytes
// @param additional_value -- additional input to the prng
// @param additional_size -- additional input length in bytes
int
ndn_random_hmacprng(const uint8_t* input_value, uint32_t input_size,
                    uint8_t* output_value, uint32_t output_size,
                    const uint8_t* seed_value, uint32_t seed_size,
                    const uint8_t* additional_value, uint32_t additional_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_RANDOM_H_
