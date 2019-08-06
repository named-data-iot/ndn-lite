/*
 * Copyright (C) 2018-2019
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
#include "../ndn-services.h"
#include "../util/bit-operations.h"
#include "../util/uniform-time.h"

static sd_self_state_t m_self_state;
static sd_sys_state_t m_sys_state;
static const uint8_t SERVICE_STATUS_MASK = 0xAA;
static uint8_t sd_buf[4096];

void
sd_init(const ndn_name_t* dev_identity_name)
{
  m_self_state.home_prefix = &dev_identity_name->components[0];
  m_self_state.device_locator_size = dev_identity_name->components_size - 1;
  for (int i = 0; i < dev_identity_name->components_size - 1; i++) {
    m_self_state.device_locator[i] = &dev_identity_name->components[i + 1];
  }
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    m_self_state.services[i].status = 0;
  }
  for (int i = 0; i < NDN_SD_SERVICES_SIZE; i++) {
    m_sys_state.interested_services[i] = NDN_SD_NONE;
    m_sys_state.cached_services[i].components_size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    m_sys_state.expire_tps[i] = 0;
  }
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
  decoder_init(&decoder, raw_int, raw_int_size);
  // TODO signature verification
  uint8_t sd_adv = NDN_SD_SD_ADV_ADV;
  uint8_t sd_query = NDN_SD_SD_QUERY;
  ndn_time_ms_t now = ndn_time_now_ms();
  if (interest.name.components[2].size != 1) {
    // unrecognized Interest, ignore it
    return NDN_SUCCESS;
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
                                  TLV_DATAARG_CONTENT_SIZE, encoder.offset,
                                  TLV_DATAARG_SIGTYPE_U8, NDN_SIG_TYPE_ECDSA_SHA256,
                                  TLV_DATAARG_IDENTITYNAME_PTR, &keys->self_identity,
                                  TLV_DATAARG_SIGKEY_PTR, &keys->self_identity_key);
          if (ret != NDN_SUCCESS) return ret;
          ndn_forwarder_put_data(data_buf, data_length);
        }
      }
    }
  }
  return NDN_SUCCESS;
}

void
sd_listen()
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
}

void
on_query_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  ndn_data_t data;
  printf("On data\n");
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
}

void
on_sd_ctl_meta_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  ndn_data_t data;
  printf("On data\n");
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
}

void
on_sd_interest_timeout (void* userdata)
{
  (void)userdata;
}

int
sd_start_adv_self_services()
{
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
  // Parameter: uint32_t (freshness period), NameComponent, NameComponent, ...
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  encoder_append_uint32_value(&encoder, SD_ADV_INTERVAL);
  for (int i = 0; i < 10; i++) {
    if (BIT_CHECK(m_self_state.services[i].status, 7)) {
      // TODO: add service status check (available, unavailable, etc.)
      encoder_append_byte_value(&encoder, m_self_state.services[i].service_id);
    }
  }
  ndn_interest_set_Parameters(&interest, sd_buf, encoder.offset);
  // TODO signature signing
  // Express Interest
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ndn_forwarder_express_interest(encoder.output_value, encoder.offset, NULL, NULL, NULL);
  return NDN_SUCCESS;
}

int
sd_query_sys_services(uint8_t service_id)
{
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
  // TODO signature signing
  // Express Interest
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                 on_sd_ctl_meta_data, on_sd_interest_timeout, NULL);
  return NDN_SUCCESS;
}

int
sd_query_service(uint8_t service_id, const ndn_name_t* granularity, bool is_any)
{
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
  // TODO signature signing
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buf, sizeof(sd_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                 on_query_data, on_sd_interest_timeout, NULL);
  return NDN_SUCCESS;
}

// static ndn_sd_context_t sd_context;

// /************************************************************/
// /*  Definition of Neighbors APIS                            */
// /************************************************************/

// static void
// _neighbors_init(void)
// {
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++i) {
//     sd_context.neighbors[i].identity.size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
//     for (uint8_t j = 0; j < NDN_APPSUPPORT_SERVICES_SIZE; ++j) {
//       sd_context.neighbors[i].services[j].status = NDN_APPSUPPORT_SERVICE_UNDEFINED;
//     }
//   }
// }

// static ndn_sd_identity_t*
// _neighbors_find_neighbor(const name_component_t* identity)
// {
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++i) {
//     if (sd_context.neighbors[i].identity.size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
//       continue;
//     }
//     if (name_component_compare(&sd_context.neighbors[i].identity, identity) == 0) {
//       return &sd_context.neighbors[i];
//     }
//   }
//   return NULL;
// }

// static ndn_sd_identity_t*
// _neighbors_add_neighbor(const name_component_t* identity)
// {
//   ndn_sd_identity_t* neighbor = _neighbors_find_neighbor(identity);
//   if (neighbor != NULL)
//     return neighbor;

//   for (uint8_t i = 0; i < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++i) {
//     if (sd_context.neighbors[i].identity.size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
//       sd_context.neighbors[i].identity = *identity;
//       return &sd_context.neighbors[i];
//     }
//   }
//   return NULL;
// }

// static int
// _neighbor_add_update_service(ndn_sd_identity_t* neighbor,
//                              const uint8_t* id_value, uint32_t id_size,
//                              const uint8_t status)
// {
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
//     if (neighbor->services[i].status == NDN_APPSUPPORT_SERVICE_UNDEFINED)
//       continue;
//     if (memcmp(neighbor->services[i].id_value, id_value,
//                neighbor->services[i].id_size > id_size?
//                id_size : neighbor->services[i].id_size) == 0) {
//       neighbor->services[i].status = status;
//       return 0;
//     }
//   }
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
//     if (neighbor->services[i].status == NDN_APPSUPPORT_SERVICE_UNDEFINED) {
//       memcpy(neighbor->services[i].id_value, id_value, id_size);
//       neighbor->services[i].id_size = id_size;
//       neighbor->services[i].status = status;
//       return 0;
//     }
//   }
//   return NDN_OVERSIZE;
// }

// // invoked when trying to find a service provider
// static ndn_sd_identity_t*
// _neighbors_find_first_service_provider(const uint8_t* id_value, uint32_t id_size)
// {
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++i) {
//     if (sd_context.neighbors[i].identity.size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE)
//       continue;
//     for (uint8_t j = 0; j < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++j) {
//       if (memcmp(sd_context.neighbors[i].services[j].id_value, id_value,
//                  sd_context.neighbors[i].services[i].id_size > id_size?
//                  id_size : sd_context.neighbors[i].services[i].id_size) == 0) {
//         return &sd_context.neighbors[i];
//       }
//     }
//   }
//   return NULL;
// }

// // invoked when receiving new advertisement from a neighbor
// static void
// _neighbor_reset_service(ndn_sd_identity_t* neighbor)
// {
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
//     neighbor->services[i].status = NDN_APPSUPPORT_SERVICE_UNDEFINED;
//   }
// }

// // invoked when the neighbor is not available
// static void
// _neighbors_remove_neighbor(const name_component_t* id)
// {
//   ndn_sd_identity_t* neighbor = _neighbors_find_neighbor(id);
//   if (neighbor != NULL) {
//     neighbor->identity.size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
//     _neighbor_reset_service(neighbor);
//   }
// }

//  /************************************************************/
//  /*  Definition of service discovery APIs                    */
//  /************************************************************/

// void
// ndn_sd_init(const ndn_name_t* home_prefix, const name_component_t* self_id)
// {
//   _neighbors_init();
//   sd_context.self.identity = *self_id;
//   sd_context.home_prefix = *home_prefix;

//   for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; i++) {
//     sd_context.self.services[i].status = NDN_APPSUPPORT_SERVICE_UNDEFINED;
//   }
// }

// ndn_service_t*
// ndn_sd_register_get_self_service(const char* prefix, uint32_t size)
// {
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
//     if (sd_context.self.services[i].status == NDN_APPSUPPORT_SERVICE_UNDEFINED)
//       continue;
//     if (memcmp(sd_context.self.services[i].id_value, prefix,
//                sd_context.self.services[i].id_size > size?
//                size : sd_context.self.services[i].id_size) == 0)
//       return &sd_context.self.services[i];
//   }
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
//     if (sd_context.self.services[i].status != NDN_APPSUPPORT_SERVICE_UNDEFINED)
//       continue;
//     sd_context.self.services[i].status = NDN_APPSUPPORT_SERVICE_AVAILABLE;
//     memcpy(&sd_context.self.services[i].id_value, prefix, size);
//     sd_context.self.services[i].id_size = size;
//     return &sd_context.self.services[i];
//   }
//   return NULL;
// }

// ndn_sd_identity_t*
// ndn_sd_find_neigbor(const name_component_t* id)
// {
//   return _neighbors_find_neighbor(id);
// }

// ndn_sd_identity_t*
// ndn_sd_find_first_service_provider(const char* id_value, uint32_t id_size)
// {
//   return _neighbors_find_first_service_provider((uint8_t*)id_value, id_size);
// }

// void
// ndn_sd_prepare_advertisement(ndn_interest_t* interest)
// {
//   // make service list and prepare the interest
//   ndn_interest_from_name(interest, &sd_context.home_prefix);

//   name_component_t comp_sd;
//   const char* str_sd = "SD-ADV";
//   name_component_from_string(&comp_sd, str_sd, strlen(str_sd));
//   ndn_name_append_component(&interest->name, &comp_sd);
//   ndn_name_append_component(&interest->name, &sd_context.self.identity);

//   ndn_encoder_t encoder;
//   encoder_init(&encoder, interest->parameters.value, NDN_INTEREST_PARAMS_BUFFER_SIZE);
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; i++) {
//     if (sd_context.self.services[i].status != NDN_APPSUPPORT_SERVICE_UNDEFINED
//         && sd_context.self.services[i].status != NDN_APPSUPPORT_SERVICE_UNAVAILABLE) {
//       name_component_t toEncode;
//       name_component_from_buffer(&toEncode, TLV_GenericNameComponent,
//                                  sd_context.self.services[i].id_value,
//                                  sd_context.self.services[i].id_size);
//       name_component_tlv_encode(&encoder, &toEncode);
//     }
//   }
//   interest->enable_Parameters = 1;
//   interest->parameters.size = encoder.offset;
// }

// void
// ndn_sd_prepare_query(ndn_interest_t* interest, name_component_t* target, ndn_service_t* service,
//                      const uint8_t* params_value, uint32_t params_size)
// {
//   ndn_interest_from_name(interest, &sd_context.home_prefix);
//   name_component_t comp_sd;
//   const char* str_sd = "SD";
//   name_component_from_string(&comp_sd, str_sd, strlen(str_sd));
//   ndn_name_append_component(&interest->name, &comp_sd);
//   ndn_name_append_component(&interest->name, target);

//   name_component_t comp_qr;
//   const char* str_qr = "QUERY";
//   name_component_from_string(&comp_qr, str_qr, strlen(str_qr));
//   ndn_name_append_component(&interest->name, &comp_qr);

//   name_component_t comp_id;
//   name_component_from_buffer(&comp_id, TLV_GenericNameComponent, service->id_value, service->id_size);
//   ndn_name_append_component(&interest->name, &comp_id);

//   if (params_value != NULL && params_size > 0) {
//     ndn_interest_set_Parameters(interest, params_value, params_size);
//   }
// }

// int
// ndn_sd_on_advertisement_process(const ndn_interest_t* interest)
// {
//   uint32_t home_len = sd_context.home_prefix.components_size;

//   // check and add neighbor
//   ndn_sd_identity_t* entry = _neighbors_add_neighbor(&interest->name.components[home_len + 1]);
//   if (!entry){
//     return NDN_OVERSIZE;
//   }

//   // reset services
//   _neighbor_reset_service(entry);
//   ndn_decoder_t decoder;
//   decoder_init(&decoder, interest->parameters.value, interest->parameters.size);
//   name_component_t toDecode;
//   for (; decoder.input_size - decoder.offset > 0;) {
//     name_component_tlv_decode(&decoder, &toDecode);
//     _neighbor_add_update_service(entry, toDecode.value, toDecode.size,
//                                  NDN_APPSUPPORT_SERVICE_AVAILABLE);
//   }
//   return 0;
// }

// int
// ndn_sd_on_query_process(const ndn_interest_t* interest, ndn_data_t* response)
// {
//   uint32_t home_len = sd_context.home_prefix.components_size;
//   ndn_service_t* entry = NULL;
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; i++) {
//     if (sd_context.self.services[i].status != NDN_APPSUPPORT_SERVICE_UNDEFINED) {
//       int r = memcmp(sd_context.self.services[i].id_value, interest->name.components[home_len + 3].value,
//                      sd_context.self.services[i].id_size > interest->name.components[home_len + 3].size?
//                      interest->name.components[home_len + 3].size : sd_context.self.services[i].id_size);
//       if (r == 0) {
//         entry = &sd_context.self.services[i];
//         break;
//       }
//     }
//   }

//   if (entry) {
//     uint8_t buffer[3];
//     ndn_encoder_t encoder;
//     encoder_init(&encoder, buffer, sizeof(buffer));
//     encoder_append_type(&encoder, TLV_SD_STATUS);
//     encoder_append_length(&encoder, 1);
//     encoder_append_byte_value(&encoder, entry->status);

//     // (Optional) ECDH_Pub_Key

//     response->name = interest->name;
//     ndn_data_set_content(response, buffer, sizeof(buffer));
//     return 0;
//   }
//   return NDN_SD_NO_MATCH_SERVCE;
// }

// int
// ndn_sd_on_query_response_process(const ndn_data_t* response)
// {
//   uint32_t home_len = sd_context.home_prefix.components_size;
//   ndn_decoder_t decoder;
//   decoder_init(&decoder, response->content_value, response->content_size);
//   uint32_t probe;
//   uint8_t status;
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   decoder_get_byte_value(&decoder, &status);

//   // try to find the neighbor (add if neighbor got deleted)
//   ndn_sd_identity_t* neighbor = _neighbors_add_neighbor(&response->name.components[home_len + 1]);

//   // update service status
//   _neighbor_add_update_service(neighbor, response->name.components[home_len + 3].value,
//                                response->name.components[home_len + 3].size, status);

//   // (Optional) ECDH bits
//   return 0;
// }

// int
// ndn_sd_on_query_timeout_process(const ndn_interest_t* interest)
// {
//   uint32_t home_len = sd_context.home_prefix.components_size;
//   _neighbors_remove_neighbor(&interest->name.components[home_len + 1]);
//   return 0;
// }
