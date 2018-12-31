/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "../ndn-lite-sec-config.h"

#ifdef NDN_LITE_SEC_BACKEND_CRYPTO_KEY_DEFAULT

#include "../ndn-lite-random.h"
#include "../ndn-lite-crypto-key.h"
#include "../sec-lib/tinycrypt/tc_ecc_dh.h"
#include "../sec-lib/tinycrypt/tc_constants.h"

void
ndn_ecc_key_set_rng(ndn_ECC_RNG_Function rng) {
  tc_uECC_set_rng(rng);
}

int
ndn_ecc_key_make_key(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                     uint8_t curve_type, uint32_t key_id)
{
  tc_uECC_Curve curve;
  switch(curve_type) {
  case NDN_ECDSA_CURVE_SECP256R1:
    curve = tc_uECC_secp256r1();
    break;
  default:
    // TODO: support other ECDSA with micro-ecc
    return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;
  }
  int r = tc_uECC_make_key(ecc_pub->key_value, ecc_prv->key_value, curve);
  if (r != TC_CRYPTO_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  ecc_pub->key_id = key_id;
  ecc_prv->key_id = key_id;
  return 0;
}

int
ndn_hmac_make_key(ndn_hmac_key_t* key, uint32_t key_id,
                  const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* personalization, uint32_t personalization_size,
                  const uint8_t* seed_value, uint32_t seed_size,
                  const uint8_t* additional_value, uint32_t additional_size,
                  uint32_t salt_size)
{
  uint8_t salt[salt_size];
  int r = ndn_random_hmacprng(personalization, personalization_size,
                              salt, sizeof(salt), seed_value, seed_size,
                              additional_value, additional_size);
  if (r != 0)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  r = ndn_random_hkdf(input_value, input_size, key->key_value, key->key_size,
                      salt, sizeof(salt));
  if (r != 0)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  key->key_id = key_id;
  return 0;
}

int
ndn_ecc_key_shared_secret(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                          uint8_t curve_type, uint8_t* output, uint32_t output_size)
{
  if (output_size < 24)
    return NDN_SEC_NOT_ENABLED_FEATURE;
  tc_uECC_Curve curve;
  switch(curve_type) {
  case NDN_ECDSA_CURVE_SECP256R1:
    curve = tc_uECC_secp256r1();
    break;
  default:
    // TODO: support other ECDSA with micro-ecc
    return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;
  }
  int r = tc_uECC_shared_secret(ecc_pub->key_value, ecc_prv->key_value, output, curve);
  if (r != TC_CRYPTO_SUCCESS) return NDN_SEC_CRYPTO_ALGO_FAILURE;
  return 0;
}

#endif // NDN_LITE_SEC_BACKEND_CRYPTO_KEY_DEFAULT
