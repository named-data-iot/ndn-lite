/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-lite-ecc.h"
#include "ndn-lite-sha.h"
#include "ndn-lite-sec-utils.h"

ndn_ecc_backend_t ndn_ecc_backend;

ndn_ecc_backend_t*
ndn_ecc_get_backend(void)
{
  return &ndn_ecc_backend;
}

uint32_t
ndn_ecc_get_pub_key_size(const ndn_ecc_pub_t* pub_key)
{
  return ndn_ecc_backend.get_pub_key_size(&pub_key->abs_key);
}

uint32_t
ndn_ecc_get_prv_key_size(const ndn_ecc_prv_t* prv_key)
{
  return ndn_ecc_backend.get_prv_key_size(&prv_key->abs_key);
}

const uint8_t*
ndn_ecc_get_pub_key_value(const ndn_ecc_pub_t* pub_key)
{
  return ndn_ecc_backend.get_pub_key_value(&pub_key->abs_key);
}

int
ndn_ecc_pub_init(ndn_ecc_pub_t* ecc_pub, const uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id)
{
  ecc_pub->curve_type = curve_type;
  ecc_pub->key_id = key_id;
  return ndn_ecc_backend.load_pub_key(&ecc_pub->abs_key, key_value, key_size);
}

int
ndn_ecc_prv_init(ndn_ecc_prv_t* ecc_prv, const uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id)
{
  ecc_prv->curve_type = curve_type;
  ecc_prv->key_id = key_id;
  return ndn_ecc_backend.load_prv_key(&ecc_prv->abs_key, key_value, key_size);
}

int
ndn_ecc_set_rng(ndn_rng_impl rng)
{
  return ndn_ecc_backend.set_rng(rng);
}

int
ndn_ecc_make_key(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                 uint8_t curve_type, uint32_t key_id)
{
  ecc_pub->key_id = key_id;
  ecc_prv->key_id = key_id;
  ecc_pub->curve_type = curve_type;
  ecc_prv->curve_type = curve_type;
  return ndn_ecc_backend.make_key(&ecc_pub->abs_key, &ecc_prv->abs_key, curve_type);
}

int
ndn_ecc_dh_shared_secret(const ndn_ecc_pub_t* ecc_pub, const ndn_ecc_prv_t* ecc_prv, uint8_t* output, uint32_t output_size)
{
  return ndn_ecc_backend.dh_shared_secret(&ecc_pub->abs_key, &ecc_prv->abs_key,
                                          ecc_prv->curve_type, output, output_size);
}

int
ndn_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
               uint8_t* output_value, uint32_t output_max_size,
               const ndn_ecc_prv_t* ecc_prv_key, uint32_t* output_used_size)
{
  uint8_t hash_result[NDN_SEC_SHA256_HASH_SIZE] = {0};
  if (ndn_sha256(input_value, input_size, hash_result) != NDN_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;

  return ndn_ecc_backend.ecdsa_sign(hash_result, sizeof(hash_result),
                                    output_value, output_max_size,
                                    &ecc_prv_key->abs_key,
                                    ecc_prv_key->curve_type, output_used_size);
}

int
ndn_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                 const uint8_t* sig_value, uint32_t sig_size,
                 const ndn_ecc_pub_t* ecc_pub_key)
{
  uint8_t hash_result[NDN_SEC_SHA256_HASH_SIZE] = {0};
  if (ndn_sha256(input_value, input_size, hash_result) != NDN_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;

  return ndn_ecc_backend.ecdsa_verify(hash_result, sizeof(hash_result),
                                      sig_value, sig_size,
                                      &ecc_pub_key->abs_key, ecc_pub_key->curve_type);
}
