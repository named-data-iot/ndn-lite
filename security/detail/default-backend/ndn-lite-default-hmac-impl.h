/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_DEFAULT_HMAC_IMPL_H
#define NDN_LITE_DEFAULT_HMAC_IMPL_H

#include <stddef.h>
#include <stdint.h>

struct abstract_hmac_key {
  /**
   * The key bytes buffer of current key.
   */
  uint8_t key_value[32];
  /**
   * The key size of key bytes.
   */
  uint32_t key_size;
};

int
ndn_lite_default_hmac_sha256(const struct abstract_hmac_key* abs_key,
                             const void* data, unsigned int data_length,
                             uint8_t* hmac_result);

int
ndn_lite_default_make_hmac_key(struct abstract_hmac_key* abs_key,
                               const uint8_t* input_value, uint32_t input_size,
                               const uint8_t* personalization, uint32_t personalization_size,
                               const uint8_t* seed_value, uint32_t seed_size,
                               const uint8_t* additional_value, uint32_t additional_size,
                               uint32_t salt_size);

int
ndn_lite_default_hkdf(const uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value, uint32_t output_size,
                      const uint8_t* seed_value, uint32_t seed_size);

int
ndn_lite_default_hmacprng(const uint8_t* input_value, uint32_t input_size,
                          uint8_t* output_value, uint32_t output_size,
                          const uint8_t* seed_value, uint32_t seed_size,
                          const uint8_t* additional_value, uint32_t additional_size);

#endif // NDN_LITE_DEFAULT_HMAC_IMPL_H
