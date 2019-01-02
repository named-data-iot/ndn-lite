/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-ecc.h"
#include "ndn-lite-sec-config.h"

void
ndn_ecc_key_set_rng(ndn_ECC_RNG_Function rng)
{
#ifdef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  tc_uECC_set_rng(rng);
#endif
}

int
ndn_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
               uint8_t* output_value, uint32_t output_max_size,
               const uint8_t* prv_key_value, uint32_t prv_key_size,
               uint8_t ecdsa_type, uint32_t* output_used_size)
{
#ifdef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  return ndn_lite_default_ecdsa_sign(input_value, input_size,
                                     output_value, output_max_size,
                                     prv_key_value, prv_key_size,
                                     ecdsa_type, output_used_size);
#endif
}

int
ndn_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                 const uint8_t* sig_value, uint32_t sig_size,
                 const uint8_t* pub_key_value,
                 uint32_t pub_key_size, uint8_t ecdsa_type)
{
#ifdef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  return ndn_lite_default_ecdsa_verify(input_value, input_size,
                                       sig_value, sig_size,
                                       pub_key_value,
                                       pub_key_size, ecdsa_type);
#endif
}

int
ndn_ecc_key_make_key(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                     uint8_t curve_type, uint32_t key_id)
{
  ecc_pub->key_id = key_id;
  ecc_prv->key_id = key_id;
  int result = 0;
#ifdef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  result = ndn_lite_default_make_ecc_key(ecc_pub->key_value, &ecc_pub->key_size,
                                         ecc_prv->key_value, &ecc_prv->key_size,
                                         curve_type);
#endif
  return result;
}

int
ndn_ecc_dh_shared_secret(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                         uint8_t curve_type, uint8_t* output, uint32_t output_size)
{
  int result = 0;
#ifdef NDN_LITE_SEC_BACKEND_ECC_DEFAULT
  result = ndn_lite_default_ecc_dh(ecc_pub->key_value, ecc_prv->key_value,
                                   curve_type, output, output_size);
#endif
  return result;
}
