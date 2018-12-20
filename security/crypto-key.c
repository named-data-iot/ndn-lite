/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "crypto-key.h"
#include "random.h"
#include "micro-ecc/uECC.h"

int
ndn_ecc_key_make_key(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                     uint8_t curve_type, uint32_t key_id,
                     ndn_ECC_RNG_Function rng_func)
{
  uECC_set_rng(rng_func);
  uECC_Curve curve = NULL;

  uint32_t key_size = curve_type;
  if (curve_type == NDN_ECDSA_CURVE_SECP256K1)
    key_size = 32;

  switch (curve_type) {
  case NDN_ECDSA_CURVE_SECP160R1:
    curve = uECC_secp160r1();
    break;
  case NDN_ECDSA_CURVE_SECP192R1:
    curve = uECC_secp192r1();
    break;
  case NDN_ECDSA_CURVE_SECP224R1:
    curve = uECC_secp224r1();
    break;
  case NDN_ECDSA_CURVE_SECP256R1:
    curve = uECC_secp256r1();
    break;
  case NDN_ECDSA_CURVE_SECP256K1:
    curve = uECC_secp256k1();
    break;
  default:
    return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;
  }
  uECC_make_key(ecc_pub->key_value, ecc_prv->key_value, curve);

  // public key
  ecc_pub->key_size = key_size*2;
  ecc_pub->curve_type = curve_type;
  ecc_pub->key_id = key_id;

  // private key
  ecc_prv->key_size = key_size;
  ecc_prv->curve_type = curve_type;
  ecc_prv->key_id = key_id;

  return 0;
}

int
ndn_hmac_make_key(ndn_hmac_key_t* key, uint32_t key_id,
                  const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* seed_value, uint32_t seed_size,
                  const uint8_t* additional_value, uint32_t additional_size)
{
  key->key_size = 32;
  key->key_id = key_id;
  return ndn_random_hmacprng(input_value, input_size,
                             key->key_value, 32,
                             seed_value, seed_size,
                             additional_value, additional_size);
}
