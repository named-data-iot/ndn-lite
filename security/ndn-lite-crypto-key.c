/*
 * Copyright (C) 2018 Tianyuan Yu, Edward Lu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-sec-config.h"
#include "ndn-lite-random.h"
#include "ndn-lite-crypto-key.h"

void
ndn_ecc_key_set_rng(ndn_ECC_RNG_Function rng) {
  tc_uECC_set_rng(rng);
}

int
ndn_ecc_key_make_key(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                     uint8_t curve_type, uint32_t key_id)
{
#ifdef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  return ndn_lite_ecc_key_make_key_tinycrypt(ecc_pub, ecc_prv,
                                             curve_type, key_id);
#endif
}

int
ndn_hmac_make_key(ndn_hmac_key_t* key, uint32_t key_id,
                  const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* personalization, uint32_t personalization_size,
                  const uint8_t* seed_value, uint32_t seed_size,
                  const uint8_t* additional_value, uint32_t additional_size,
                  uint32_t salt_size)
{
#ifdef NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
  return ndn_lite_hmac_make_key_tinycrypt(key, key_id,
                                          input_value, input_size,
                                          personalization, personalization_size,
                                          seed_value, seed_size,
                                          additional_value, additional_size,
                                          salt_size);
#endif
}

int
ndn_ecc_key_shared_secret(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                          uint8_t curve_type, uint8_t* output, uint32_t output_size)
{
#ifdef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  return ndn_lite_ecc_key_shared_secret_tinycrypt(ecc_pub, ecc_prv,
                                                  curve_type, output,
                                                  output_size);
#endif
}
