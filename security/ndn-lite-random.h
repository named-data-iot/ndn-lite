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

/**
 * Use HMAC-KDF Algorithm to generate a secure HMAC key.
 * This function requires proper entropy source.
 * @param input_value. Input. Random input that requires KDF.
 * @param input_size. Input. Random input length in bytes.
 * @param output_value. Output. Buffer to receive output.
 * @param output_size. Input. Size of the output buffer.
 * @param seed_value. Input. Entropy to mix into the prng
 * @param seed_size. Input. Entropy length in bytes
 * @return 0 if there is no error.
 */
int
ndn_random_hkdf(const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_size,
                const uint8_t* seed_value, uint32_t seed_size);

/**
 * Use HMAC-PRNG Algorithm to generate pseudo-random bytes.
 * This function requires proper entropy source.
 * @param input_value. Input. Personalization string.
 * @param input_size. Input. Personalization length in bytes.
 * @param output_value. Output. Buffer to receive output.
 * @param output_size. Input. Size of the output buffer.
 * @param seed_value. Input. Entropy to mix into the prng, highly recommend larger than 32 bytes.
 * @param seed_size. Input. Entropy length in bytes, highly recommend larger than 32 bytes.
 * @param additional_value. Input. Additional input to the prng
 * @param additional_size. Input. Additional input length in bytes
 * @return 0 if there is no error.
 */
int
ndn_random_hmacprng(const uint8_t* input_value, uint32_t input_size,
                    uint8_t* output_value, uint32_t output_size,
                    const uint8_t* seed_value, uint32_t seed_size,
                    const uint8_t* additional_value, uint32_t additional_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_RANDOM_H_
