/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "../ndn-lite-sec-config.h"

#ifdef NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT

#include "../ndn-lite-random.h"
#include "../detail/sec-lib/tinycrypt/tc_hmac_prng.h"
#include "../ndn-lite-sign-verify.h"

int
ndn_random_hkdf(const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_size,
                const uint8_t* seed_value, uint32_t seed_size)
{
  uint8_t prk[32] = {0};
  uint32_t used_bytes = 0;
  ndn_signer_hmac_sign(input_value, input_size, prk, 32, seed_value, seed_size, &used_bytes);

  int iter;
  if (output_size % 32)
    iter = output_size / 32 + 1;
  else
    iter = output_size / 32;
  uint8_t t[32] = {0};
  uint8_t cat[33] = {0};
  uint8_t okm[32 * iter];
  for (uint8_t i = 0; i < 32 * iter; i++)
    okm[i] = 0;
  uint8_t table[16] = {0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  uint8_t t_first[2] = {0x00, 0x01};
  for (int i = 0; i < iter; ++i) {
    if (i == 0) {
      ndn_signer_hmac_sign(t_first, sizeof(t_first), t, 32, prk, 32, &used_bytes);
      memcpy(okm + i * 32, t, 32);
    }
    else {
      memcpy(cat, t, 32);
      cat[32] = table[i];
      ndn_signer_hmac_sign(cat, 33, t, 32, prk, 32, &used_bytes);
      memcpy(okm + i * 32, t, 32);
    }
  }
  memcpy(output_value, okm, output_size);
  return 0;
}

int
ndn_random_hmacprng(const uint8_t* input_value, uint32_t input_size,
                    uint8_t* output_value, uint32_t output_size,
                    const uint8_t* seed_value, uint32_t seed_size,
                    const uint8_t* additional_value, uint32_t additional_size)
{
  struct tc_hmac_prng_struct h;
  tc_hmac_prng_init(&h, input_value, input_size);

  if (seed_size < 32)
  {
    uint8_t min_seed[32] = {0};
    memcpy(min_seed, seed_value, seed_size);
    tc_hmac_prng_reseed(&h, min_seed, sizeof(min_seed), additional_value, additional_size);
    tc_hmac_prng_generate(output_value, output_size, &h);
  }
  else
  {
    tc_hmac_prng_reseed(&h, seed_value, seed_size, additional_value, additional_size);
    tc_hmac_prng_generate(output_value, output_size, &h);
  }
  return 0;
}

#endif // NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT