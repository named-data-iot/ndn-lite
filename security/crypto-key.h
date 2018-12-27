/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_CRYPTO_KEY_H
#define NDN_SECURITY_CRYPTO_KEY_H

#include "../encode/name.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ndn_ECC_RNG_Function type
 *
 * This type is the same as micro-ecc/uECC.h::uECC_RNG_Function
 *
 * The RNG function should fill 'size' random bytes into 'dest'.
 * It should return 1 if 'dest' was filled with random data,
 * or 0 if the random data could not be generated.
 * The filled-in values should be either truly random, or from a cryptographically-secure PRNG.
 * Setting a correctly functioning RNG function improves the resistance to side-channel attacks.
 **/

typedef int (*ndn_ECC_RNG_Function)(uint8_t *dest, unsigned size);

typedef struct ndn_ecc_pub {
  uint32_t key_id;
  uint8_t key_value[64];
  uint32_t key_size;
  uint8_t curve_type;
} ndn_ecc_pub_t;

typedef struct ndn_ecc_prv {
  uint32_t key_id;
  uint8_t key_value[32];
  uint32_t key_size;
  uint8_t curve_type;
} ndn_ecc_prv_t;

typedef struct ndn_hmac_key {
  uint32_t key_id;
  uint32_t key_size;
  uint8_t key_value[32];
} ndn_hmac_key_t;

typedef struct ndn_aes_key {
  uint32_t key_id;
  uint8_t key_value[32];
  uint32_t key_size;
} ndn_aes_key_t;

static inline int
ndn_ecc_pub_init(ndn_ecc_pub_t* ecc_pub, uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id)
{
  if (key_size > 64)
    return NDN_SEC_WRONG_KEY_SIZE;
  memcpy(ecc_pub->key_value, key_value, key_size);
  ecc_pub->key_size = key_size;
  ecc_pub->curve_type = curve_type;
  ecc_pub->key_id = key_id;
  return 0;
}

static inline int
ndn_ecc_prv_init(ndn_ecc_prv_t* ecc_prv, uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id)
{
  if (key_size > 32)
    return NDN_SEC_WRONG_KEY_SIZE;
  memcpy(ecc_prv->key_value, key_value, key_size);
  ecc_prv->key_size = key_size;
  ecc_prv->curve_type = curve_type;
  ecc_prv->key_id = key_id;
  return 0;
}


static inline int
ndn_hmac_key_init(ndn_hmac_key_t* key, uint8_t* key_value,
                  uint32_t key_size, uint32_t key_id)
{
  if (key_size > 32)
    return NDN_SEC_WRONG_KEY_SIZE;
  key->key_size = key_size;
  memcpy(key->key_value, key_value, key_size);
  key->key_id = key_id;
  return 0;
}

static inline int
ndn_aes_key_init(ndn_aes_key_t* key, uint8_t* key_value,
                 uint32_t key_size, uint32_t key_id)
{
  if (key_size > 32)
    return NDN_SEC_WRONG_KEY_SIZE;
  key->key_size = key_size;
  memcpy(key->key_value, key_value, key_size);
  key->key_id = key_id;
  return 0;
}

// int
// ndn_ecc_key_make_key(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
//                      uint8_t curve_type, uint32_t key_id, ndn_ECC_RNG_Function rng_func);

// // @param input_value -- personalization string
// // @param input_size -- personalization length in bytes
// // @param output_value -- buffer to receive output
// // @param output_size -- size of the output buffer
// // @param seed_value -- entropy to mix into the prng
// // @param seed_size -- entropy length in bytes
// // @param additional_value -- additional input to the prng
// // @param additional_size -- additional input length in bytes
// int
// ndn_hmac_make_key(ndn_hmac_key_t* key, uint32_t key_id,
//                   const uint8_t* input_value, uint32_t input_size,
//                   const uint8_t* seed_value, uint32_t seed_size,
//                   const uint8_t* additional_value, uint32_t additional_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_CRYPTO_KEY_H
