/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "access-control.h"
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

static uint8_t sd_buf[4096];

typedef struct ac_key {
  uint32_t key_id;
  uint32_t expires_at;
} ac_key_t;

typedef struct ndn_access_control {
  uint8_t access_services[10];
  ac_key_t access_keys[10];
  uint8_t self_services[2];
  ac_key_t ekeys[2];
} ndn_access_control_t;

ndn_access_control_t _ac_self_state;
bool _ac_initialized = false;

void
_init_ac_state()
{
  for (int i = 0; i < 10; i++) {
    _ac_self_state.access_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    _ac_self_state.access_services[i] = NDN_SD_NONE;
  }
  for (int i = 0; i < 2; i++) {
    _ac_self_state.ekeys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    _ac_self_state.self_services[i] = NDN_SD_NONE;
  }
  _ac_initialized = true;
}

void
_on_ekey_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse Data
  ndn_data_t data;
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
  printf("Receive EKEY packet with name: \n");
  ndn_name_print(&data.name);

  // get key: decrypt the key
  uint32_t expires_in = 0;
  uint8_t value[36];
  uint32_t used_size = 0;
  ndn_parse_encrypted_payload(data.content_value, data.content_size,
                              value, &used_size, 10002); // SEC_BOOT_AES_KEY_ID = 10002;
  expires_in = *((uint32_t*)value + 4);

  // store it into key_storage
  ndn_aes_key_t* key = NULL;
  ndn_time_ms_t now = ndn_time_now_ms();
  uint32_t keyid;
  ndn_rng((uint8_t*)&keyid, 4);
  uint8_t service = data.name.components[3].value[0];
  for (int i = 0; i < 2; i++) {
    if (_ac_self_state.self_services[i] == service) {
      _ac_self_state.ekeys[i].key_id = keyid;
      _ac_self_state.ekeys[i].expires_at = expires_in + now;
    }
  }
  ndn_key_storage_get_empty_aes_key(&key);
  ndn_aes_key_init(key, value, 16, keyid);
}

void
_on_dkey_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse Data
  ndn_data_t data;
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
  printf("Receive EKEY packet with name: \n");
  ndn_name_print(&data.name);

  // get key: decrypt the key
  uint32_t expires_in = 0;
  uint8_t value[36];
  uint32_t used_size;
  ndn_parse_encrypted_payload(data.content_value, data.content_size,
                              value, &used_size, 10002); // SEC_BOOT_AES_KEY_ID = 10002;
  expires_in = *((uint32_t*)value + 4);

  // store it into key_storage
  ndn_aes_key_t* key = NULL;
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
  ndn_key_storage_get_empty_aes_key(&key);
  ndn_aes_key_init(key, value, 16, keyid);
}

int
_express_ekey_interest(uint8_t service)
{
  // send /home/AC/EKEY/<the service provided by my self> to the controller
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
  ndn_signed_interest_digest_sign(&interest);

  // Express Interest
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  ret = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret != 0) return ret;
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset, _on_ekey_data, NULL, NULL);
  if (ret != 0) {
    printf("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  printf("Send AC Interest packet with name: \n");
  ndn_name_print(&interest.name);
  return NDN_SUCCESS;
}

int
_express_dkey_interest(uint8_t service)
{
  // send /home/AC/DKEY/<the services that I need to access> to the controller
  int ret = 0;
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

  //signature signing
  ndn_signed_interest_digest_sign(&interest);

  // Express Interest
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  ret = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret != 0) return ret;
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset, _on_ekey_data, NULL, NULL);
  if (ret != 0) {
    printf("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  printf("Send AC Interest packet with name: \n");
  ndn_name_print(&interest.name);
  return NDN_SUCCESS;
}

void
register_service_require_ek(uint8_t service)
{
  if (!_ac_initialized) {
    _init_ac_state();
  }
  for (int i = 0; i < 2; i++) {
    if (_ac_self_state.self_services[i] == NDN_SD_NONE) {
      _ac_self_state.self_services[i] = service;
    }
  }
}

void
register_access_request(uint8_t service)
{
  if (!_ac_initialized) {
    _init_ac_state();
  }
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.access_services[i] == NDN_SD_NONE) {
      _ac_self_state.access_services[i] = service;
    }
  }
}

void
ac_after_bootstrapping()
{
  if (!_ac_initialized) {
    _init_ac_state();
  }
  // send /home/AC/EKEY/<the service provided by my self> to the controller
  for (int i = 0; i < 2; i++) {
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
