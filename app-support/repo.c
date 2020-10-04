/*
 * Copyright (C) 2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#define ENABLE_NDN_LOG_INFO 1
#define ENABLE_NDN_LOG_DEBUG 1
#define ENABLE_NDN_LOG_ERROR 1

#include "../util/logger.h"
#include "../app-support/pub-sub.h"
#include "../forwarder/forwarder.h"
#include "../util/msg-queue.h"
#include "../encode/key-storage.h"

#include "repo.h"

#define INVALID_NONCE (uint32_t)(-1)
#define TLV_REPO_NONCE 128

static uint8_t repo_buf[1024];

repo_state_t repo_state;
bool repo_initialized = false;

void
_repo_erase_soft_state(nonce_to_msg_t* handle)
{
  handle->msg_size = 0;
  handle->nonce = INVALID_NONCE;
  NDN_LOG_DEBUG("[REPO] Soft state earsing...\n");
}

nonce_to_msg_t*
ndn_repo_find_handle(uint32_t nonce)
{
  for (int i = 0; i < 10; i++) {
    if (repo_state.dict[i].nonce == nonce)
      return &repo_state.dict[i];
  }
  return NULL;
}

void
_on_repo_publish_notify_ack(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  NDN_LOG_DEBUG("[REPO] Receiving notification ack\n");

  // erase handle
  _repo_erase_soft_state((nonce_to_msg_t*)userdata);
}

void
_on_repo_publish_notify_timeout(void* userdata)
{
  _repo_erase_soft_state((nonce_to_msg_t*)userdata);
}

void
_repo_publish_notify(nonce_to_msg_t* handle)
{
  ndn_interest_t notify;
  ndn_interest_init(&notify);
  ndn_name_init(&notify.name);
  ndn_name_append_component(&notify.name, &ndn_key_storage_get_self_identity(handle->service)->components[0]);
  ndn_name_append_string_component(&notify.name, "repo", strlen("repo"));
  ndn_name_append_string_component(&notify.name, "insert", strlen("insert"));
  ndn_name_append_string_component(&notify.name, "notify", strlen("notify"));

  uint8_t notify_param[500];
  ndn_encoder_t encoder;
  encoder_init(&encoder, notify_param, sizeof(notify_param));
  ndn_name_tlv_encode(&encoder, ndn_key_storage_get_self_identity(handle->service));
  encoder_append_type(&encoder, TLV_REPO_NONCE);
  encoder_append_length(&encoder, sizeof(uint32_t));
  encoder_append_uint32_value(&encoder, handle->nonce);
  // asssume no forwarding hint

  // erase the soft state after 5s

  // expressing interest
  ndn_interest_set_CanBePrefix(&notify, false);
  ndn_interest_set_MustBeFresh(&notify, false);
  ndn_interest_set_Parameters(&notify, encoder.output_value, encoder.offset);

  encoder_init(&encoder, repo_buf, sizeof(repo_buf));
  int ret = ndn_interest_tlv_encode(&encoder, &notify);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[REPO] Cannot encode\n");
  }
  NDN_LOG_DEBUG("[REPO] Notifying ");NDN_LOG_DEBUG_NAME(&notify.name);
  ndn_forwarder_express_interest(encoder.output_value, encoder.offset, _on_repo_publish_notify_ack, _on_repo_publish_notify_timeout, handle);
}

int
_on_repo_msg_interest(const uint8_t* interest, uint32_t interest_size, void* userdata)
{
  int ret = -1;
  ndn_interest_t msg_interest;
  ndn_interest_from_block(&msg_interest, interest, interest_size);
  NDN_LOG_DEBUG("[REPO] ");NDN_LOG_DEBUG_NAME(&msg_interest.name);

  ndn_decoder_t decoder;
  decoder_init(&decoder, msg_interest.name.components[msg_interest.name.components_size - 2].value,
                         msg_interest.name.components[msg_interest.name.components_size - 2].size);
  uint32_t nonce;
  decoder_get_uint32_value(&decoder, &nonce);
  nonce_to_msg_t* handle = ndn_repo_find_handle(nonce);
  if (handle == NULL) {
    NDN_LOG_ERROR("[REPO] Cannot find handle\n");
    return NDN_OVERSIZE;
  }

  ndn_data_t msg;
  ndn_data_init(&msg);
  msg.name = msg_interest.name;
  ndn_data_set_content(&msg, handle->msg, handle->msg_size);
  ndn_metainfo_init(&msg.metainfo);
  ndn_metainfo_set_content_type(&msg.metainfo, NDN_CONTENT_TYPE_BLOB);

  ndn_encoder_t encoder;
  encoder_init(&encoder, repo_buf, sizeof(repo_buf));
  ndn_data_tlv_encode_digest_sign(&encoder, &msg);
  ret = ndn_forwarder_put_data(encoder.output_value, encoder.offset);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[REPO] Forwarder cannot put, error code = %d\n", ret);
    return ret;
  }
  return NDN_FWD_STRATEGY_SUPPRESS;
}

void
ndn_repo_init()
{
  // register callback for all services
  ndn_name_t msg_prefix;
  for (int i = 0; i < NDN_SEC_CERT_SIZE; i++) {
    ndn_name_init(&msg_prefix);
    if (ndn_key_storage_get_instance()->self_identity_key[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      memcpy(&msg_prefix, &ndn_key_storage_get_instance()->self_identity[i], sizeof(ndn_name_t));
      ndn_name_append_string_component(&msg_prefix, "msg", strlen("msg"));
      ndn_forwarder_register_name_prefix(&msg_prefix, _on_repo_msg_interest, NULL);
    }
  }
  for (int i = 0; i < 10; i++) {
    repo_state.dict[i].nonce = INVALID_NONCE;
  }
  repo_initialized = true;
}


nonce_to_msg_t*
ndn_repo_get_new_publish_handle()
{
  for (int i = 0; i < 10; i++) {
    if (repo_state.dict[i].nonce == INVALID_NONCE)
      return &repo_state.dict[i];
  }
  return NULL;
}

int
ndn_repo_set_publish_handle(nonce_to_msg_t* handle, uint8_t* msg_value, uint32_t msg_size, uint8_t service)
{
  if (handle == NULL)
    return NDN_OVERSIZE;
  if (msg_size > 500)
    return NDN_OVERSIZE;
  
  uint8_t nonce[4];
  ndn_rng(nonce, sizeof(nonce));
  memcpy(&handle->nonce, nonce, sizeof(nonce));
  memcpy(handle->msg, msg_value, msg_size);
  handle->msg_size = msg_size;
  handle->service = service;
  return NDN_SUCCESS;
}

int
ndn_repo_publish(uint8_t* msg_value, uint32_t msg_size, uint8_t service)
{
  if (!repo_initialized)
    return NDN_OVERSIZE;

  int ret = -1;
  nonce_to_msg_t* handle = ndn_repo_get_new_publish_handle();
  if (handle == NULL) {
    NDN_LOG_ERROR("[REPO] Cannot get new handle\n");
    return NDN_OVERSIZE;
  }
  
  ret = ndn_repo_set_publish_handle(handle, msg_value, msg_size, service);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[REPO] Cannot set handle, error code = %d\n", ret);
    return ret;
  }
  _repo_publish_notify(handle);
  return NDN_SUCCESS;
}

void
ndn_repo_publish_cmd_param(ndn_name_t* expected_name, uint8_t service)
{
   ndn_encoder_t encoder;
   uint8_t param_buf[300];
   encoder_init(&encoder, param_buf, sizeof(param_buf));
   ndn_name_tlv_encode(&encoder, expected_name);
   encoder_append_type(&encoder, 206);
   encoder_append_length(&encoder, sizeof(uint32_t));
   uint32_t nonce;
   uint8_t get_nonce[4];
   ndn_rng(get_nonce, sizeof(get_nonce));
   memcpy(&nonce, get_nonce, sizeof(get_nonce));
   encoder_append_uint32_value(&encoder, nonce);
   // no register root prefix

   ndn_repo_publish(encoder.output_value, encoder.offset, service);

}
