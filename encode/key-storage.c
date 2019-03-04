/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "key-storage.h"

static ndn_key_storage_t storage;

ndn_key_storage_t*
ndn_key_storage_init(void)
{
  storage.is_bootstrapped = 0;
  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    storage.ecc_pub_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    storage.ecc_prv_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    storage.hmac_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;

    if (i <= NDN_SEC_ENCRYPTION_KEYS_SIZE)
      storage.aes_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
  }
  return &storage;
}

ndn_key_storage_t*
ndn_key_storage_get_instance(void)
{
  return &storage;
}

int
ndn_key_storage_set_anchor(const ndn_data_t* trust_anchor)
{
  memcpy(&storage.trust_anchor, trust_anchor, sizeof(ndn_data_t));

  // TBD parse key
  // ndn_ecc_pub_init(&storage.trust_anchor_key, uint8_t* key_value,
  //                  uint32_t key_size, NDN_ECDSA_CURVE_SECP256R1, uint32_t key_id)

  storage.is_bootstrapped = 1;
  return 0;
}

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_empty_hmac_key(ndn_hmac_key_t** hmac)
{
  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (storage.hmac_keys[i].key_id == NDN_SEC_INVALID_KEY_ID) {
      *hmac = &storage.hmac_keys[i];
      return;
    }
  }
  hmac = NULL;
}

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_empty_ecc_key(ndn_ecc_pub_t** pub, ndn_ecc_prv_t** prv)
{
  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (storage.ecc_pub_keys[i].key_id == NDN_SEC_INVALID_KEY_ID) {
      *pub = &storage.ecc_pub_keys[i];
      *prv = &storage.ecc_prv_keys[i];
      return;
    }
  }
  *pub = NULL;
  *prv = NULL;
}

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_empty_aes_key(ndn_aes_key_t** aes)
{
  for (uint8_t i = 0; i < NDN_SEC_ENCRYPTION_KEYS_SIZE; i++) {
    if (storage.aes_keys[i].key_id == NDN_SEC_INVALID_KEY_ID) {
      *aes = &storage.aes_keys[i];
      return;
    }
  }
  *aes = NULL;
}

void
ndn_key_storage_delete_hmac_key(uint32_t key_id)
{
  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (storage.hmac_keys[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      if (key_id == storage.hmac_keys[i].key_id) {
        storage.hmac_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
        return;
      }
    }
  }
}

void
ndn_key_storage_delete_ecc_key(uint32_t key_id)
{
  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (storage.ecc_pub_keys[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      if (key_id == storage.ecc_pub_keys[i].key_id) {
        storage.ecc_pub_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
        storage.ecc_prv_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
        return;
      }
    }
  }
}

void
ndn_key_storage_delete_aes_key(uint32_t key_id)
{
  for (uint8_t i = 0; i < NDN_SEC_ENCRYPTION_KEYS_SIZE; i++) {
    if (storage.aes_keys[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      if (key_id == storage.aes_keys[i].key_id) {
        storage.aes_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
        return;
      }
    }
  }
}

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_hmac_key(uint32_t key_id, ndn_hmac_key_t** hmac)
{
  for (uint8_t i = 0; i <NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (storage.hmac_keys[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      if (key_id == storage.hmac_keys[i].key_id) {
        *hmac = &storage.hmac_keys[i];
        return;
      }
    }
  }
  *hmac = NULL;
}

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_ecc_key(uint32_t key_id, ndn_ecc_pub_t** pub, ndn_ecc_prv_t** prv)
{
  for (uint8_t i = 0; i <NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (storage.ecc_pub_keys[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      if (key_id == storage.ecc_pub_keys[i].key_id) {
        *pub = &storage.ecc_pub_keys[i];
        *prv = &storage.ecc_prv_keys[i];
        return;
      }
    }
  }
  *pub = NULL;
  *prv = NULL;
}

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_aes_key(uint32_t key_id, ndn_aes_key_t** aes)
{
  for (uint8_t i = 0; i <NDN_SEC_ENCRYPTION_KEYS_SIZE; i++) {
    if (storage.aes_keys[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      if (key_id == storage.aes_keys[i].key_id) {
        *aes = &storage.aes_keys[i];
        return;
      }
    }
  }
  *aes = NULL;
}
