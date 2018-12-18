/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#ifndef NDN_APP_SUPPORT_SERVICE_DISCOVERY_H
#define NDN_APP_SUPPORT_SERVICE_DISCOVERY_H

#include "../encode/interest.h"
#include "../encode/data.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_service {
  uint8_t status;
  uint8_t id_value[NDN_APPSUPPORT_SERVICE_ID_SIZE];
  uint32_t id_size;
} ndn_service_t;

typedef struct ndn_sd_identity {
  name_component_t identity;
  ndn_service_t services[NDN_APPSUPPORT_SERVICES_SIZE];
} ndn_sd_identity_t;

typedef struct ndn_sd_context {
  ndn_name_t home_prefix;
  ndn_sd_identity_t self;
  ndn_sd_identity_t neighbors[NDN_APPSUPPORT_NEIGHBORS_SIZE];
} ndn_sd_context_t;

void
ndn_sd_init(const ndn_name_t* home_prefix, const name_component_t* self_id);

ndn_service_t*
ndn_sd_register_get_self_service(const char* id_value, uint32_t id_size);

static inline int
ndn_sd_set_service_status(ndn_service_t* service, uint8_t status)
{
  service->status = status;
  return 0;
}

ndn_sd_identity_t*
ndn_sd_find_neigbor(const name_component_t* id);

ndn_sd_identity_t*
ndn_sd_find_first_service_provider(const char* id_value, uint32_t id_size);

void
ndn_sd_prepare_advertisement(ndn_interest_t* interest);

void
ndn_sd_prepare_query(ndn_interest_t* interest, name_component_t* target, ndn_service_t* service,
                     const uint8_t* params_value, uint32_t params_size);

// function used in receiver side onInterest callback
int
ndn_sd_on_advertisement_process(const ndn_interest_t* interest);

// function used in receiver side onInterest callback
int
ndn_sd_on_query_process(const ndn_interest_t* interest, ndn_data_t* response);

// function used in sender side onData callback
int
ndn_sd_on_query_response_process(const ndn_data_t * response);

// function used in sender side onInterestTimeout callback
int
ndn_sd_on_query_timeout_process(const ndn_interest_t* interest);

#ifdef __cplusplus
}
#endif

#endif // NDN_APP_SUPPORT_SERVICE_DISCOVERY_H
