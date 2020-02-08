/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "access-control.h"
#include "security-bootstrapping.h"
#include "../ndn-services.h"
#include "../encode/key-storage.h"
#include "../encode/signed-interest.h"
#include "../encode/encrypted-payload.h"
#include "../forwarder/forwarder.h"
#include "../security/ndn-lite-aes.h"
#include "../security/ndn-lite-ecc.h"
#include "../security/ndn-lite-hmac.h"
#include "../security/ndn-lite-rng.h"
#include "../util/msg-queue.h"
#include "../util/uniform-time.h"

/* Logging Level: ERROR, DEBUG */
#define ENABLE_NDN_LOG_ERROR 1
#define ENABLE_NDN_LOG_DEBUG 1
#include "../util/logger.h"

/* Encoding buffer for Access Control module */
static uint8_t ac_buf[1024];

/**
 * The structure of AccessControlKey.
 */
typedef struct ac_key {
  /**
   * KeyID, should be globally unique in KeyStorage.
   */
  uint32_t key_id;
  /**
   * KeyLifetime, the key expiration time is Now + KeyLifetime.
   */
  uint32_t expires_at;
} ac_key_t;

/**
 * The structure of AccessControlState.
 */
typedef struct ndn_access_control {
  /**
   * AccessServices for this identity that would use DecryptionKey.
   */
  uint8_t access_services[10];
  /**
   * DecryptionKeys used for by identity's AccessService.
   */
  ac_key_t access_keys[10];
  /**
   * RegisterServices for this identity that would use EncryptionKey.
   */
  uint8_t self_services[10];
  /**
   * EncryptionKeys used for by identity's RegisterServices.
   */
  ac_key_t ekeys[10];
} ndn_access_control_t;

ndn_access_control_t _ac_self_state;
bool _ac_initialized = false;

/* Initialize the AccessControlState */
void
_init_ac_state()
{
  for (int i = 0; i < 10; i++) {
    _ac_self_state.access_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    _ac_self_state.access_services[i] = NDN_SD_NONE;
  }
  for (int i = 0; i < 10; i++) {
    _ac_self_state.ekeys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    _ac_self_state.self_services[i] = NDN_SD_NONE;
  }
  _ac_initialized = true;
}

/**
 *  Response for EncryptionKey onData.
 *  This will parse the EncryptionKey Data with KeyID SEC_BOOT_AES_KEY_ID Key, which is already
 *  generated from Bootstrapping. The EncryptionKey's expiration time will be calculated.
 *  Decoded EncryptionKey will be stored at KeyStorage with KeyID filled with a uint32_t random number.
 */
void
_on_ekey_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse Data
  ndn_data_t data;
  int ret = -1;

  // should verify with TrustAnchor Key
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ret = ndn_data_tlv_decode_ecdsa_verify(&data, raw_data, data_size, &storage->trust_anchor_key);
  if (ret) {
    NDN_LOG_ERROR("EncryptionKey Data Verification failure, ErrorCode = %d\n", ret);
  }

  NDN_LOG_DEBUG("Receive EncryptionKey Data with Name: ");
  NDN_LOG_DEBUG_NAME(&data.name);

  // get key: decrypt the key
  uint32_t expires_in = 0;
  uint8_t value[30] = {0};
  uint32_t used_size = 0;
  ret = ndn_parse_encrypted_payload(data.content_value, data.content_size,
                                    value, &used_size, SEC_BOOT_AES_KEY_ID);
  if (ret || used_size == 0) {
    NDN_LOG_ERROR("Parse encrypted payload failure. ErrorCode = %d\n", ret);
  }

  ndn_decoder_t decoder;
  decoder_init(&decoder, value + NDN_AES_BLOCK_SIZE, sizeof(expires_in));
  decoder_get_uint32_value(&decoder, &expires_in);

  NDN_LOG_DEBUG("EncryptionKey KeyLifetime = %u ms\n", expires_in);

  // store it into key_storage
  ndn_time_ms_t now = ndn_time_now_ms();
  uint32_t keyid;
  ndn_rng((uint8_t*)&keyid, 4);
  uint8_t service = data.name.components[3].value[0];
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.self_services[i] == service) {
      _ac_self_state.ekeys[i].key_id = keyid;
      _ac_self_state.ekeys[i].expires_at = expires_in + now;
    }
  }
  ndn_aes_key_t* key = ndn_key_storage_get_empty_aes_key();
  if (key != NULL) {
    ndn_aes_key_init(key, value, NDN_AES_BLOCK_SIZE, keyid);
  }
  else {
    NDN_LOG_ERROR("No empty AES key in local key storage.");
  }
}

/**
 *  Response for DecryptionKey onData.
 *  This will parse the DecryptionKey Data with KeyID SEC_BOOT_AES_KEY_ID Key, which is already
 *  generated from Bootstrapping. The DecryptionKey's expiration time will be calculated.
 *  Decoded DecryptionKey will be stored at KeyStorage with KeyID filled with a uint32_t random number.
 */
void
_on_dkey_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse Data
  ndn_data_t data;
  int ret = -1;

  // should verify with TrustAnchor Key
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ret = ndn_data_tlv_decode_ecdsa_verify(&data, raw_data, data_size, &storage->trust_anchor_key);
  if (ret) {
    NDN_LOG_ERROR("DecryptionKey Data Verification failure, ErrorCode = %d\n", ret);
  }

  NDN_LOG_DEBUG("Receive DecryptionKey Data with Name: ");
  NDN_LOG_DEBUG_NAME(&data.name);

  // get key: decrypt the key
  uint32_t expires_in = 0;
  uint8_t value[30] = {0};
  uint32_t used_size = 0;

  ret = ndn_parse_encrypted_payload(data.content_value, data.content_size,
                                    value, &used_size, SEC_BOOT_AES_KEY_ID);
  if (ret || used_size == 0) {
    NDN_LOG_ERROR("Parse encrypted payload failure. ErrorCode = %d\n", ret);
  }

  ndn_decoder_t decoder;
  decoder_init(&decoder, value + NDN_AES_BLOCK_SIZE, sizeof(expires_in));
  decoder_get_uint32_value(&decoder, &expires_in);

  NDN_LOG_DEBUG("DecryptionKey KeyLifetime = %u ms\n", expires_in);

  // store it into key_storage
  ndn_time_ms_t now = ndn_time_now_ms();
  uint32_t keyid;
  ndn_rng((uint8_t*)&keyid, 4);
  uint8_t service = data.name.components[3].value[0];
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.access_services[i] == service) {
      _ac_self_state.access_keys[i].key_id = keyid;
      _ac_self_state.access_keys[i].expires_at = expires_in + now;
    }
  }
  ndn_aes_key_t* key = ndn_key_storage_get_empty_aes_key();
  if (key != NULL) {
    ndn_aes_key_init(key, value, 16, keyid);
  }
  else {
    NDN_LOG_ERROR("No empty AES key in local key storage.");
  }
}

int _express_dkey_interest(uint8_t service);
int _express_ekey_interest(uint8_t service);

void
_on_ekey_int_timeout(void* userdata)
{
  NDN_LOG_DEBUG("[ACCESSCTL] EKEY interest timeout. Resend the Interest.");
  uint8_t service_id = *(uint8_t*)userdata;
  _express_ekey_interest(service_id);
}

void
_on_dkey_int_timeout(void* userdata)
{
  NDN_LOG_DEBUG("[ACCESSCTL] DKEY interest timeout. Resend the Interest.");
  uint8_t service_id = *(uint8_t*)userdata;
  _express_dkey_interest(service_id);
}

/**
 *  EncryptionKey Interesing expressing.
 *  This will express a signed Interest with CanBePrefix flag set.
 */
int
_express_ekey_interest(uint8_t service)
{
  int ret = 0;
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ret = ndn_name_append_component(&interest.name, &storage->self_identity.components[0]);
  if (ret != 0) return ret;
  uint8_t ac = NDN_SD_AC;
  ret = ndn_name_append_bytes_component(&interest.name, &ac, 1);
  if (ret != 0) return ret;
  uint8_t ekey = NDN_SD_AC_EK;
  ret = ndn_name_append_bytes_component(&interest.name, &ekey, 1);
  if (ret != 0) return ret;
  ret = ndn_name_append_bytes_component(&interest.name, &service, 1);
  if (ret != 0) return ret;

  //signature signing
  ndn_signed_interest_ecdsa_sign(&interest, &storage->self_identity, &storage->self_identity_key);

  // Express Interest
  ndn_encoder_t encoder;
  encoder_init(&encoder, ac_buf, sizeof(ac_buf));
  ndn_interest_set_CanBePrefix(&interest, 1);
  ret = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret != 0) return ret;
  static uint8_t service_id = 0;
  service_id = service;
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset, _on_ekey_data, _on_ekey_int_timeout, &service_id);
  if (ret != 0) {
    NDN_LOG_ERROR("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  NDN_LOG_DEBUG("Send EncryptionKey Interest with Name: ");
  NDN_LOG_DEBUG_NAME(&interest.name);
  return NDN_SUCCESS;
}

/**
 *  DecryptionKey Interesing expressing.
 *  This will express a signed Interest with CanBePrefix flag set.
 */
int
_express_dkey_interest(uint8_t service)
{
  int ret = -1;
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ret = ndn_name_append_component(&interest.name, &storage->self_identity.components[0]);
  if (ret != 0) return ret;
  uint8_t ac = NDN_SD_AC;
  ret = ndn_name_append_bytes_component(&interest.name, &ac, 1);
  if (ret != 0) return ret;
  uint8_t dkey = NDN_SD_AC_DK;
  ret = ndn_name_append_bytes_component(&interest.name, &dkey, 1);
  if (ret != 0) return ret;
  ret = ndn_name_append_bytes_component(&interest.name, &service, 1);
  if (ret != 0) return ret;

  // signature signing
  ndn_signed_interest_ecdsa_sign(&interest, &storage->self_identity, &storage->self_identity_key);

  // Express Interest
  ndn_encoder_t encoder;
  encoder_init(&encoder, ac_buf, sizeof(ac_buf));
  ndn_interest_set_CanBePrefix(&interest, 1);
  ret = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret != 0) return ret;
  static uint8_t service_id = 0;
  service_id = service;
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset, _on_dkey_data, _on_ekey_int_timeout, &service_id);
  if (ret != 0) {
    NDN_LOG_ERROR("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  NDN_LOG_DEBUG("Send DecryptionKey Interest with Name: ");
  NDN_LOG_DEBUG_NAME(&interest.name);
  return NDN_SUCCESS;
}

/**
 *  RegisterServices.
 */
ndn_aes_key_t*
ndn_ac_get_key_for_service(uint8_t service)
{
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.self_services[i] == service) {
      return ndn_key_storage_get_aes_key(_ac_self_state.ekeys[i].key_id);
    }
    if (_ac_self_state.access_services[i] == service) {
      return ndn_key_storage_get_aes_key(_ac_self_state.access_keys[i].key_id);
    }
  }
  return NULL;
}

/**
 *  RegisterServices.
 */
void
ndn_ac_register_encryption_key_request(uint8_t service)
{
  if (!_ac_initialized) {
    _init_ac_state();
  }
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.self_services[i] == NDN_SD_NONE) {
      _ac_self_state.self_services[i] = service;
      return;
    }
  }
}

/**
 *  AccessServices.
 */
void
ndn_ac_register_access_request(uint8_t service)
{
  if (!_ac_initialized) {
    _init_ac_state();
  }
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.access_services[i] == NDN_SD_NONE) {
      _ac_self_state.access_services[i] = service;
      return;
    }
  }
}

/**
 *  AccessControl start. Should be called after Bootstrapping.
 */
void
ndn_ac_after_bootstrapping()
{
  if (!_ac_initialized) {
    _init_ac_state();
  }
  // send /home/AC/EKEY/<the service provided by my self> to the controller
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.self_services[i] != NDN_SD_NONE) {
      _express_ekey_interest(_ac_self_state.self_services[i]);
    }
  }
  // send /home/AC/DKEY/<the services that I need to access> to the controller
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.access_services[i] != NDN_SD_NONE) {
      _express_dkey_interest(_ac_self_state.access_services[i]);
    }
  }
  // e.g. Temp sensor produce under TEMP, access SD
  // 1. send /home/AC/EKEY/TEMP to obtain encryption key
  // 2. send /home/AC/DKEY/SD to obtain decryption key
}
