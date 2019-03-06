/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#ifndef NDN_ENCODE_KEY_STORAGE_H
#define NDN_ENCODE_KEY_STORAGE_H

#include "data.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to implement keys storage and management.
 */
typedef struct ndn_key_storage {
  /**
   * The trust anchor storage.
   */
  ndn_data_t trust_anchor;
  /**
   * The trust anchor public key.
   */
  ndn_ecc_pub_t trust_anchor_key;
  /**
   * Boolean indicating whether the device is bootstrapped.
   */
  uint8_t is_bootstrapped;
  /**
   * The self signing key storage.
   */
  ndn_ecc_pub_t ecc_pub_keys[NDN_SEC_SIGNING_KEYS_SIZE];
  ndn_ecc_prv_t ecc_prv_keys[NDN_SEC_SIGNING_KEYS_SIZE];
  ndn_hmac_key_t hmac_keys[NDN_SEC_SIGNING_KEYS_SIZE];
  /**
   * The self encryption/decryption key storage.
   */
  ndn_aes_key_t aes_keys[NDN_SEC_ENCRYPTION_KEYS_SIZE];
} ndn_key_storage_t;

/**
 * Init an in-library key storage structure.
 * @return The pointer to the initialized key storage structure
 */
ndn_key_storage_t*
ndn_key_storage_init(void);

/**
 * Get a running instance of key storage structure.
 * @return the pointer to the ket storage instance.
 */
ndn_key_storage_t*
ndn_key_storage_get_instance(void);

/**
 * Set trust anchor for the key storage structure.
 * @param trust_anchor. Input. Trust anchor to configure the key storage structure.
 * @return 0 if there is no error.
 */
int
ndn_key_storage_set_anchor(const ndn_data_t* trust_anchor);

/**
 * Get an empty HMAC key pointer from key storage structure.
 * @param hmac. Output. Pass NULL pointers into the function to get empty HMAC key pointers.
 */
void
ndn_key_storage_get_empty_hmac_key(ndn_hmac_key_t** hmac);

/**
 * Get an empty ECC key pointer from key storage structure.
 * @param pub. Output. Pass NULL pointers into the function to get empty ECC key pointers.
 * @param prv. Output. Pass NULL pointers into the function to get empty ECC key pointers.
 */
void
ndn_key_storage_get_empty_ecc_key(ndn_ecc_pub_t** pub, ndn_ecc_prv_t** prv);

/**
 * Get an empty AES-128 key pointer from key storage structure.
 * @param aes. Output. Pass NULL pointers into the function to get empty ECC key pointers.
 */
void
ndn_key_storage_get_empty_aes_key(ndn_aes_key_t** aes);

/**
 * Delete a HMAC key by searching corresponding unique key id.
 * @param key_id. Input. Key id of the key to delete.
 */
void
ndn_key_storage_delete_hmac_key(uint32_t key_id);

/**
 * Delete a ECC key by searching corresponding unique key id.
 * @param key_id. Input. Key id of the key to delete.
 */
void
ndn_key_storage_delete_ecc_key(uint32_t key_id);

/**
 * Delete a AES-128 key by searching corresponding unique key id.
 * @param key_id. Input. Key id of the key to delete.
 */
void
ndn_key_storage_delete_aes_key(uint32_t key_id);

/**
 * Get an empty HMAC key pointer from key storage structure.
 * @param key_id. Input. Key id which indicates the key to fetch.
 * @param hmac. Output. Pass NULL pointers into the function to get output hmac key pointers.
 */
void
ndn_key_storage_get_hmac_key(uint32_t key_id, ndn_hmac_key_t** hmac);

/**
 * Get an empty ECC key pointer from key storage structure.
 * @param key_id. Input. Key id which indicates the key to fetch.
 * @param hmac. Output. Pass NULL pointers into the function to get output ECC key pointers.
 */
void
ndn_key_storage_get_ecc_key(uint32_t key_id, ndn_ecc_pub_t** pub, ndn_ecc_prv_t** prv);

/**
 * Get an empty AES-128 key pointer from key storage structure.
 * @param key_id. Input. Key id which indicates the key to fetch.
 * @param hmac. Output. Pass NULL pointers into the function to get output AES-128 key pointers.
 */
void
ndn_key_storage_get_aes_key(uint32_t key_id, ndn_aes_key_t** aes);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODE_KEY_STORAGE_H
