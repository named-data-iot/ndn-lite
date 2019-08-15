/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "service-discovery.h"
#include "../encode/wrapper-api.h"
#include "../encode/key-storage.h"
#include "../forwarder/forwarder.h"
#include "../ndn-services.h"
#include "../util/bit-operations.h"
#include "../util/uniform-time.h"
#include "../util/msg-queue.h"

/**
 * The structure to represent a NDN service.
 */
typedef struct ndn_service {
  /**
   * a bit vector:
   * index 7 (leftmost) bit. whether initialized. 0: uninitialized 1: initialized
   * index 6 bit. whether to advertise. 0: no adv, 1: adv.
   * index 0-5 bits. The state of the service.
   */
  uint8_t status;
  /**
   * The NDN service ID.
   */
  uint8_t service_id;
} ndn_service_t;

/**
 * The structure to keep the state of one's own services
 */
typedef struct sd_self_state {
  /**
   * The home prefix component
   */
  const name_component_t* home_prefix;
  /**
   * The locator name components of the device
   */
  const name_component_t* device_locator[NDN_NAME_COMPONENTS_SIZE];
  uint8_t device_locator_size;
  /**
   * Device IDs
   */
  ndn_service_t services[NDN_SD_SERVICES_SIZE];
} sd_self_state_t;

/**
 * The structure to keep the cached service information in the system
 */
typedef struct sd_sys_state {
  uint8_t interested_services[NDN_SD_SERVICES_SIZE];
  ndn_name_t cached_services[NDN_SD_SERVICES_SIZE];
  ndn_time_ms_t expire_tps[NDN_SD_SERVICES_SIZE];
} sd_sys_state_t;

static sd_self_state_t m_self_state;
static sd_sys_state_t m_sys_state;
static bool m_has_initialized = false;
static bool m_has_bootstrapped = false;
static const uint8_t SERVICE_STATUS_MASK = 0x3F;
static uint8_t sd_buf[4096];
static ndn_time_ms_t m_next_adv;

void
ndn_sd_init()
{
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    m_self_state.services[i].status = 0;
  }
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    m_sys_state.interested_services[i] = NDN_SD_NONE;
    m_sys_state.cached_services[i].components_size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    m_sys_state.expire_tps[i] = 0;
  }
  m_next_adv = 0;
  m_has_initialized = true;
}

void
ndn_sd_after_bootstrapping()
{
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  m_self_state.home_prefix = &storage->self_identity.components[0];
  m_self_state.device_locator_size = storage->self_identity.components_size - 1;
  for (int i = 0; i < storage->self_identity.components_size - 1; i++) {
    m_self_state.device_locator[i] = &storage->self_identity.components[i + 1];
  }
  m_has_bootstrapped = true;
}

int
sd_add_or_update_self_service(uint8_t service_id, bool adv, uint8_t status_code)
{
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    if (m_self_state.services[i].service_id == service_id) {
      BIT_SET(m_self_state.services[i].status, 7);
      if (adv) {
        BIT_SET(m_self_state.services[i].status, 6);
      }
      BITMASK_CLEAR(m_self_state.services[i].status, SERVICE_STATUS_MASK);
      m_self_state.services[i].status += status_code;
      return NDN_SUCCESS;
    }
  }
  bool added = false;
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    if (!BIT_CHECK(m_self_state.services[i].status, 7)) {
      m_self_state.services[i].service_id = service_id;
      BIT_SET(m_self_state.services[i].status, 7);
      if (adv) {
        BIT_SET(m_self_state.services[i].status, 6);
      }
      BITMASK_CLEAR(m_self_state.services[i].status, SERVICE_STATUS_MASK);
      m_self_state.services[i].status += status_code;
      added = true;
      break;
    }
  }
  if (added) {
    return NDN_SUCCESS;
  }
  else {
    return NDN_OVERSIZE;
  }
}

int
sd_add_or_update_cached_service(const ndn_name_t* service_name, uint64_t expire_time)
{
  ndn_time_ms_t now = ndn_time_now_ms();
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    if (m_sys_state.cached_services[i].components_size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      // empty cache, skip
      continue;
    }
    if (m_sys_state.expire_tps[i] < now) {
      // outdated cache, delete it
      m_sys_state.cached_services[i].components_size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
      m_sys_state.expire_tps[i] = 0;
    }
    if (0 == ndn_name_compare(&m_sys_state.cached_services[i], service_name)) {
      // find existing
      m_sys_state.expire_tps[i] = expire_time;
      return NDN_SUCCESS;
    }
  }
  bool added = false;
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    if (m_sys_state.cached_services[i].components_size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      memcpy(&m_sys_state.cached_services[i], service_name, sizeof(ndn_name_t));
      m_sys_state.expire_tps[i] = expire_time;
      added = true;
    }
  }
  if (added) {
    return NDN_SUCCESS;
  }
  else {
    return NDN_OVERSIZE;
  }
}

int
sd_add_interested_service(uint8_t service_id)
{
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    if (m_sys_state.interested_services[i] == service_id) {
      return NDN_SUCCESS;
    }
  }
  bool added = false;
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    if (m_sys_state.interested_services[i] == NDN_SD_NONE) {
      m_sys_state.interested_services[i] = service_id;
      added = true;
    }
  }
  if (added) {
    return NDN_SUCCESS;
  }
  else {
    return NDN_OVERSIZE;
  }
}

int
on_sd_interest(const uint8_t* raw_int, uint32_t raw_int_size, void* userdata)
{
  ndn_interest_t interest;
  ndn_decoder_t decoder;
  // decoder_init(&decoder, raw_int, raw_int_size);
  ndn_interest_from_block(&interest, raw_int, raw_int_size);
  printf("Receive SD related Interest packet with name: \n");
  ndn_name_print(&interest.name);
  // TODO signature verification
  uint8_t sd_adv = NDN_SD_SD_ADV_ADV;
  uint8_t sd_query = NDN_SD_SD_QUERY;
  ndn_time_ms_t now = ndn_time_now_ms();
  if (interest.name.components[2].size != 1) {
    // unrecognized Interest, ignore it
    return NDN_FWD_STRATEGY_MULTICAST;
  }
  if (memcmp(interest.name.components[2].value, &sd_adv, 1)) {
    // adv Interest packet
    decoder_init(&decoder, interest.parameters.value, interest.parameters.size);
    uint32_t freshness_period = 0;
    decoder_get_uint32_value(&decoder, &freshness_period);
    ndn_time_ms_t expire_tp = now + (uint64_t)freshness_period;
    ndn_name_t service_name;
    while (decoder.offset < decoder.input_size) {
      uint8_t service_type = NDN_SD_NONE;
      decoder_get_byte_value(&decoder, &service_type);
      for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
        if (m_sys_state.interested_services[i] == service_type) {
          ndn_name_init(&service_name);
          ndn_name_append_component(&service_name, &interest.name.components[0]);
          ndn_name_append_bytes_component(&service_name, &service_type, 1);
          for (int i = 3; i < interest.name.components_size - 1; i++) {
            ndn_name_append_component(&service_name, &interest.name.components[i]);
          }
          sd_add_or_update_cached_service(&service_name, expire_tp);
        }
      }
    }
  }
  else if (memcmp(interest.name.components[2].value, &sd_query, 1)) {
    // query Interest packet
    // check whether current device is interested in the service
    uint8_t interested_service = interest.name.components[3].value[0];
    for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
      if (m_sys_state.interested_services[i] == interested_service) {
        ndn_encoder_t encoder;
        encoder_init(&encoder, sd_buf, sizeof(sd_buf));
        for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
          if (m_sys_state.cached_services[i].components_size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE
              && m_sys_state.cached_services[i].components[1].value[0] == interested_service
              && m_sys_state.expire_tps[i] > now) {
            ndn_name_tlv_encode(&encoder, &m_sys_state.cached_services[i]);
            encoder_append_uint32_value(&encoder, (uint32_t)(m_sys_state.expire_tps[i] - now));
          }
        }
        if (encoder.offset > 0) {
          size_t data_length = 0;
          uint8_t data_buf[4096];
          ndn_key_storage_t* keys = ndn_key_storage_get_instance();
          int ret = tlv_make_data(data_buf, sizeof(data_buf), &data_length,
                                  TLV_DATAARG_NAME_PTR, &interest.name,
                                  TLV_DATAARG_CONTENT_BUF, sd_buf,
                                  TLV_DATAARG_CONTENT_SIZE, encoder.offset);
                                  // TLV_DATAARG_SIGTYPE_U8, NDN_SIG_TYPE_ECDSA_SHA256,
                                  // TLV_DATAARG_IDENTITYNAME_PTR, &keys->self_identity,
                                  // TLV_DATAARG_SIGKEY_PTR, &keys->self_identity_key);
          if (ret != NDN_SUCCESS) return NDN_FWD_STRATEGY_MULTICAST;
          ndn_forwarder_put_data(data_buf, data_length);
        }
      }
    }
  }
  return NDN_FWD_STRATEGY_MULTICAST;
}

void
sd_listen(ndn_face_intf_t *face)
{
  ndn_name_t listen_prefix;
  ndn_name_init(&listen_prefix);
  ndn_name_append_component(&listen_prefix, m_self_state.home_prefix);
  uint8_t sd = NDN_SD_SD;
  ndn_name_append_bytes_component(&listen_prefix, &sd, 1);
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  ndn_name_tlv_encode(&encoder, &listen_prefix);
  ndn_forwarder_register_prefix(encoder.output_value, encoder.offset, on_sd_interest, NULL);
  // Register outgoing route
  ndn_forwarder_add_route(face, encoder.output_value, encoder.offset);
}

void
on_query_or_sd_meta_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  ndn_data_t data;
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
  printf("Receive SD related Data packet with name: \n");
  ndn_name_print(&data.name);
  ndn_time_ms_t now = ndn_time_now_ms();
  ndn_name_t service_full_name;
  uint32_t freshness_period = 0;
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  while (decoder.offset < decoder.input_size) {
    ndn_name_init(&service_full_name);
    ndn_name_tlv_decode(&decoder, &service_full_name);
    decoder_get_uint32_value(&decoder, &freshness_period);
    sd_add_or_update_cached_service(&service_full_name, now + (uint64_t)freshness_period);
  }
}

void
on_sd_interest_timeout (void* userdata)
{
  // do nothing for now
  (void)userdata;
}

int
sd_start_adv_self_services()
{
  if (!m_has_initialized || !m_has_bootstrapped) {
    return NDN_STATE_NOT_INITIALIZED;
  }
  int service_cnt;
  ndn_time_ms_t now = ndn_time_now_ms();
  if (now < m_next_adv) {
    ndn_msgqueue_post(NULL, sd_start_adv_self_services, NULL, NULL);
    return NDN_SUCCESS;
  }
  m_next_adv = now + (uint64_t)SD_ADV_INTERVAL;
  // Format: /[home-prefix]/SD/ADV/[locator]
  int ret = 0;
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ret = ndn_name_append_component(&interest.name, m_self_state.home_prefix);
  if (ret != 0) return ret;
  uint8_t sd = NDN_SD_SD;
  uint8_t sd_adv = NDN_SD_SD_ADV_ADV;
  ret = ndn_name_append_bytes_component(&interest.name, &sd, 1);
  if (ret != 0) return ret;
  ret = ndn_name_append_bytes_component(&interest.name, &sd_adv, 1);
  if (ret != 0) return ret;
  for (int i = 0; i < m_self_state.device_locator_size; i++) {
    ret = ndn_name_append_component(&interest.name, m_self_state.device_locator[i]);
    if (ret != 0) return ret;
  }
  ndn_interest_set_MustBeFresh(&interest, true);
  // Parameter: uint32_t (freshness period), byte array
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  encoder_append_uint32_value(&encoder, SD_ADV_INTERVAL);
  service_cnt = 0;
  for (int i = 0; i < 10; i++) {
    if (BIT_CHECK(m_self_state.services[i].status, 7)) {
      // TODO: add service status check (available, unavailable, etc.)
      encoder_append_byte_value(&encoder, m_self_state.services[i].service_id);
      service_cnt ++;
    }
  }
  ndn_interest_set_Parameters(&interest, sd_buf, encoder.offset);
  // TODO signature signing
  // Express Interest
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  ret = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret != 0) return ret;
  if (service_cnt > 0) {
    ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset, on_query_or_sd_meta_data, NULL, NULL);
  }
  if (ret != 0) {
    printf("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  printf("Send adv Interest packet with name: \n");
  ndn_name_print(&interest.name);
  ndn_msgqueue_post(NULL, sd_start_adv_self_services, NULL, NULL);
  return NDN_SUCCESS;
}

int
sd_query_sys_services(const uint8_t* service_ids, size_t size)
{
  if (!m_has_initialized || !m_has_bootstrapped) {
    return NDN_STATE_NOT_INITIALIZED;
  }
  // format: /[home-prefix]/SD-CTL/meta
  int ret = 0;
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ret = ndn_name_append_component(&interest.name, m_self_state.home_prefix);
  if (ret != 0) return ret;
  uint8_t sd_ctl = NDN_SD_SD_CTL;
  uint8_t sd_ctl_meta = NDN_SD_SD_CTL_META;
  ret = ndn_name_append_bytes_component(&interest.name, &sd_ctl, 1);
  if (ret != 0) return ret;
  ret = ndn_name_append_bytes_component(&interest.name, &sd_ctl_meta, 1);
  if (ret != 0) return ret;
  ndn_interest_set_MustBeFresh(&interest, true);
  ndn_interest_set_Parameters(&interest, service_ids, size);

  // TODO signature signing
  // Express Interest
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                       on_query_or_sd_meta_data, on_sd_interest_timeout, NULL);
  if (ret != 0) {
    printf("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  printf("Send SD/META Interest packet with name: \n");
  ndn_name_print(&interest.name);
  return NDN_SUCCESS;
}

int
sd_query_service(uint8_t service_id, const ndn_name_t* granularity, bool is_any)
{
  if (!m_has_initialized || !m_has_bootstrapped) {
    return NDN_STATE_NOT_INITIALIZED;
  }
  // Format: /[home-prefix]/SD/[service]/[granularity]/[descriptor: ANY, ALL]
  int ret = 0;
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ret = ndn_name_append_component(&interest.name, m_self_state.home_prefix);
  if (ret != 0) return ret;
  uint8_t sd = NDN_SD_SD;
  ret = ndn_name_append_bytes_component(&interest.name, &sd, 1);
  if (ret != 0) return ret;
  ret = ndn_name_append_bytes_component(&interest.name, &service_id, 1);
  if (ret != 0) return ret;
  ret = ndn_name_append_name(&interest.name, granularity);
  if (ret != 0) return ret;
  if (is_any) {
    ret = ndn_name_append_string_component(&interest.name, "ANY", strlen("ANY"));
  }
  else {
    ret = ndn_name_append_string_component(&interest.name, "ALL", strlen("ALL"));
  }
  if (ret != 0) return ret;
  ndn_interest_set_MustBeFresh(&interest, true);
  // send Interest out
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                       on_query_or_sd_meta_data, on_sd_interest_timeout, NULL);
  if (ret != 0) {
    printf("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  printf("Send SD query Interest packet with name: \n");
  ndn_name_print(&interest.name);
  return NDN_SUCCESS;
}
