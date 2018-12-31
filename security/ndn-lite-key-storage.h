/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#ifndef NDN_SECURITY_KEY_STORAGE_H
#define NDN_SECURITY_KEY_STORAGE_H

#include "ndn-lite-crypto-key.h"
#include "../encode/data.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_key_storage {
  // trust anchor storage
  ndn_data_t trust_anchor;

  // trust anchor public key
  ndn_ecc_pub_t trust_anchor_key;

  // boolean
  uint8_t is_bootstrapped;

  // self signing key storage
  ndn_ecc_pub_t ecc_pub_keys[NDN_SEC_SIGNING_KEYS_SIZE];
  ndn_ecc_prv_t ecc_prv_keys[NDN_SEC_SIGNING_KEYS_SIZE];
  ndn_hmac_key_t hmac_keys[NDN_SEC_SIGNING_KEYS_SIZE];

  // self encryption/decryption key storage
  ndn_aes_key_t aes_keys[NDN_SEC_ENCRYPTION_KEYS_SIZE];

} ndn_key_storage_t;

ndn_key_storage_t*
ndn_key_storage_init(void);

ndn_key_storage_t*
ndn_key_storage_get_instance(void);

int
ndn_key_storage_set_anchor(const ndn_data_t* trust_anchor);

// get empty key functions

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_empty_hmac_key(ndn_hmac_key_t** hmac);

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_empty_ecc_key(ndn_ecc_pub_t** pub, ndn_ecc_prv_t** prv);

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_empty_aes_key(ndn_aes_key_t** aes);


// delete key functions

void
ndn_key_storage_delete_hmac_key(uint32_t key_id);

void
ndn_key_storage_delete_ecc_key(uint32_t key_id);

void
ndn_key_storage_delete_aes_key(uint32_t key_id);

// get key functions

// pass NULL pointers into the function to get output hmac key pointers
void
ndn_key_storage_get_hmac_key(uint32_t key_id, ndn_hmac_key_t** hmac);

// pass NULL pointers into the function to get output ecc key pointers
void
ndn_key_storage_get_ecc_key(uint32_t key_id, ndn_ecc_pub_t** pub, ndn_ecc_prv_t** prv);

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_aes_key(uint32_t key_id, ndn_aes_key_t** aes);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_KEY_STORAGE_H
