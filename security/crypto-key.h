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

typedef struct ndn_ecc_pub {
  uint8_t key_id[4];
  uint8_t key_value[64];
  uint32_t key_size;
  uint8_t curve_type;
} ndn_ecc_pub_t;

typedef struct ndn_ecc_prv {
  uint8_t key_id[4];
  uint8_t key_value[32];
  uint32_t key_size;
  uint8_t curve_type;
} ndn_ecc_prv_t;

typedef struct ndn_hmac_key {
  uint8_t key_id[4];
  uint8_t key_size;
  uint8_t key_value[32];
} ndn_hmac_key_t;

static inline int
ndn_ecc_pub_init(ndn_ecc_pub_t* ecc_pub, uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id)
{
  if (key_size > 64)
    return NDN_ERROR_WRONG_KEY_SIZE;
  memcpy(ecc_pub->key_value, key_value, key_size);
  ecc_pub->key_size = key_size;
  ecc_pub->curve_type = curve_type;
  ecc_pub->key_id[0] = (key_id >> 24) & 0xFF;
  ecc_pub->key_id[1] = (key_id >> 16) & 0xFF;
  ecc_pub->key_id[2] = (key_id >> 8) & 0xFF;
  ecc_pub->key_id[3] = key_id & 0xFF;
  return 0;
}

static inline int
ndn_ecc_prv_init(ndn_ecc_prv_t* ecc_prv, uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id)
{
  if (key_size > 32)
    return NDN_ERROR_WRONG_KEY_SIZE;
  memcpy(ecc_prv->key_value, key_value, key_size);
  ecc_prv->key_size = key_size;
  ecc_prv->curve_type = curve_type;
  ecc_prv->key_id[0] = (key_id >> 24) & 0xFF;
  ecc_prv->key_id[1] = (key_id >> 16) & 0xFF;
  ecc_prv->key_id[2] = (key_id >> 8) & 0xFF;
  ecc_prv->key_id[3] = key_id & 0xFF;
  return 0;
}


static inline int
ndn_hmac_key_init(ndn_hmac_key_t* key, uint8_t* key_value,
                  uint32_t key_size, uint32_t key_id)
{
  if (key_size > 32)
    return NDN_ERROR_WRONG_KEY_SIZE;
  key->key_size = key_size;
  memcpy(key->key_value, key_value, key_size);
  key->key_id[0] = (key_id >> 24) & 0xFF;
  key->key_id[1] = (key_id >> 16) & 0xFF;
  key->key_id[2] = (key_id >> 8) & 0xFF;
  key->key_id[3] = key_id & 0xFF;
  return 0;
}

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_CRYPTO_KEY_H
