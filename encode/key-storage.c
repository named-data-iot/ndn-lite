/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "key-storage.h"

static ndn_key_storage_t storage;
bool _key_storage_initialized = false;

void
_ndn_key_storage_init(void)
{
  ndn_name_init(&storage.self_identity);
  ndn_data_init(&storage.self_cert);
  ndn_data_init(&storage.trust_anchor);
  storage.self_identity_key.key_id = NDN_SEC_INVALID_KEY_ID;
  storage.trust_anchor_key.key_id = NDN_SEC_INVALID_KEY_ID;
  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    storage.ecc_pub_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    storage.ecc_prv_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    storage.hmac_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    storage.trusted_ecc_pub_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;

    if (i < NDN_SEC_ENCRYPTION_KEYS_SIZE)
      storage.aes_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
  }
  _key_storage_initialized = true;
}

ndn_key_storage_t*
ndn_key_storage_get_instance(void)
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();
  return &storage;
}

int
ndn_key_storage_set_trust_anchor(const ndn_data_t* trust_anchor)
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();
  memcpy(&storage.trust_anchor, trust_anchor, sizeof(ndn_data_t));
  uint32_t anchor_keyid = key_id_from_cert_name(&trust_anchor->name);
  int ret = ndn_ecc_pub_init(&storage.trust_anchor_key,
                             trust_anchor->content_value + (trust_anchor->content_size - NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE),
                             NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE, NDN_ECDSA_CURVE_SECP256R1, anchor_keyid);
  if (ret != NDN_SUCCESS) return ret;
  return NDN_SUCCESS;
}

int
ndn_key_storage_add_trusted_certificate(const ndn_data_t* certificate)
{
  uint32_t keyid = key_id_from_cert_name(&certificate->name);
  // find an empty ECC key
  ndn_ecc_pub_t* pub_key = NULL;
  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (storage.trusted_ecc_pub_keys[i].key_id == NDN_SEC_INVALID_KEY_ID) {
      pub_key = &storage.trusted_ecc_pub_keys[i];
    }
  }
  // load the certificate key into trusted ecc pub keys
  int ret = ndn_ecc_pub_init(pub_key,
                             certificate->content_value + (certificate->content_size - NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE),
                             NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE, NDN_ECDSA_CURVE_SECP256R1, keyid);
  if (ret != NDN_SUCCESS) return ret;
  return NDN_SUCCESS;
}

int
ndn_key_storage_set_self_identity(const ndn_data_t* self_cert, const ndn_ecc_prv_t* self_prv_key)
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();
  memcpy(&storage.self_cert, self_cert, sizeof(ndn_data_t));
  memcpy(&storage.self_identity_key, self_prv_key, sizeof(ndn_ecc_prv_t));
  for (int i = 0; i < self_cert->name.components_size - 4; i++) {
    ndn_name_append_component(&storage.self_identity, &self_cert->name.components[i]);
  }
  return NDN_SUCCESS;
}

ndn_hmac_key_t*
ndn_key_storage_get_empty_hmac_key()
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();
  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (storage.hmac_keys[i].key_id == NDN_SEC_INVALID_KEY_ID) {
      return &storage.hmac_keys[i];
    }
  }
  return NULL;
}

// pass NULL pointers into the function to get empty ecc key pointers
void
ndn_key_storage_get_empty_ecc_key(ndn_ecc_pub_t** pub, ndn_ecc_prv_t** prv)
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();
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

ndn_aes_key_t*
ndn_key_storage_get_empty_aes_key()
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();
  for (uint8_t i = 0; i < NDN_SEC_ENCRYPTION_KEYS_SIZE; i++) {
    if (storage.aes_keys[i].key_id == NDN_SEC_INVALID_KEY_ID) {
      return &storage.aes_keys[i];
    }
  }
  return NULL;
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
ndn_hmac_key_t*
ndn_key_storage_get_hmac_key(uint32_t key_id)
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();
  for (uint8_t i = 0; i <NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (storage.hmac_keys[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      if (key_id == storage.hmac_keys[i].key_id) {
        return &storage.hmac_keys[i];
      }
    }
  }
  return NULL;
}

ndn_ecc_pub_t*
ndn_key_storage_get_ecc_pub_key(uint32_t key_id)
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();

  if (storage.trust_anchor_key.key_id == key_id) {
    return &storage.trust_anchor_key;
  }

  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (key_id == storage.ecc_pub_keys[i].key_id) {
      return &storage.ecc_pub_keys[i];
    }
    if (key_id == storage.trusted_ecc_pub_keys[i].key_id) {
      return &storage.trusted_ecc_pub_keys[i];
    }
  }
  return NULL;
}

ndn_ecc_prv_t*
ndn_key_storage_get_ecc_prv_key(uint32_t key_id)
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();

  for (uint8_t i = 0; i < NDN_SEC_SIGNING_KEYS_SIZE; i++) {
    if (key_id == storage.ecc_prv_keys[i].key_id) {
      return &storage.ecc_prv_keys[i];
    }
  }
  return NULL;
}

ndn_aes_key_t*
ndn_key_storage_get_aes_key(uint32_t key_id)
{
  if (!_key_storage_initialized)
    _ndn_key_storage_init();

  for (uint8_t i = 0; i <NDN_SEC_ENCRYPTION_KEYS_SIZE; i++) {
    if (key_id == storage.aes_keys[i].key_id) {
      return &storage.aes_keys[i];
    }
  }
  return NULL;
}
