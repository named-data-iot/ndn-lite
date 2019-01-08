/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-ecc.h"
#include "ndn-lite-sec-utils.h"

ndn_ecc_backend_t ndn_ecc_backend;

*ndn_ecc_backend_t
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
ndn_ecc_load_pub_key(ndn_ecc_pub_t* pub_key,
                     uint8_t* key_value, uint32_t key_size)
{
  return ndn_ecc_backend.load_pub_key(&pub_key->abs_key, key_value, key_size);
}

int
ndn_ecc_load_prv_key(ndn_ecc_prv_t* prv_key,
                     uint8_t* key_value, uint32_t key_size)
{
  return ndn_ecc_backend.load_prv_key(&prv_key->abs_key, key_value, key_size);
}

void
ndn_ecc_set_rng(ndn_ECC_RNG_Function rng)
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
ndn_ecc_dh_shared_secret(const ndn_ecc_pub_t* ecc_pub, const ndn_ecc_prv_t* ecc_prv,
                         uint8_t curve_type, uint8_t* output, uint32_t output_size)
{
  return ndn_ecc_backend.dh_shared_secret(&ecc_pub->abs_key, &ecc_prv->abs_key,
                                              curve_type, output, output_size);
}

int
ndn_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
               uint8_t* output_value, uint32_t output_max_size,
               const ndn_ecc_prv_t* ecc_prv_key,
               uint8_t ecdsa_type, uint32_t* output_used_size)
{
  return ndn_ecc_backend.ecdsa_sign(input_value, input_size,
                                    output_value, output_max_size,
                                    &ecc_prv_key->abs_key,
                                    ecdsa_type, output_used_size);
}

int
ndn_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                 const uint8_t* sig_value, uint32_t sig_size,
                 const ndn_ecc_pub_t* ecc_pub_key,
                 uint8_t ecdsa_type)
{
  return ndn_ecc_backend.ecdsa_verify(input_value, input_size,
                                      sig_value, sig_size,
                                      &ecc_pub_key->abs_key, ecdsa_type);
}
