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

/**
 * The structure to represent a NDN service.
 */
typedef struct ndn_service {
  /**
   * The NDN service status.
   */  
  uint8_t status;
  /**
   * The NDN service ID.
   */    
  uint8_t id_value[NDN_APPSUPPORT_SERVICE_ID_SIZE];
  /**
   * Size of service ID.
   */    
  uint32_t id_size;
} ndn_service_t;

/**
 * The structure to implement neighbors management in Access Control.
 */
typedef struct ndn_sd_identity {
  /**
   * The neighbor identity.
   */ 
  name_component_t identity;
  /**
   * The neighbor identity's service list.
   */ 
  ndn_service_t services[NDN_APPSUPPORT_SERVICES_SIZE];
} ndn_sd_identity_t;

/**
 * The structure to implement state storage and management in Service Discovery.
 */
typedef struct ndn_sd_context {
  /**
   * The home prefix of local network.
   */ 
  ndn_name_t home_prefix;
  /**
   * The local state manager identity (and services provided).
   */ 
  ndn_sd_identity_t self;
  /**
   * The neighbor list.
   */ 
  ndn_sd_identity_t neighbors[NDN_APPSUPPORT_NEIGHBORS_SIZE];
} ndn_sd_context_t;

/**
 * Init a Service Discovery State structure.
 * @param home_prefix. Input. The network home prefix to configure the state manager.
 * @param self_id. Input. The local state manager identity.
 */
void
ndn_sd_init(const ndn_name_t* home_prefix, const name_component_t* self_id);

/**
 * Get a pointer to a NDN service by searching its NDN service ID.
 * @param id_value. Input. Service ID buffer.
 * @param id_size. Input. Size of input service ID.
 * @return pointer to the NDN service if it exists.
 */
ndn_service_t*
ndn_sd_register_get_self_service(const char* id_value, uint32_t id_size);

/**
 * Set service status of a NDN service.
 * @param service. Input. The NDN service whose service status will be set.
 * @param status. Input. Service status value.
 * @return 0 if there is no error.
 */
static inline int
ndn_sd_set_service_status(ndn_service_t* service, uint8_t status)
{
  service->status = status;
  return 0;
}

/**
 * Find a neighbor in the neighbor list by searching its identity.
 * @param id. Input. The neighbor identity searched.
 * @return pointer to the neighbor identity if it exists.
 */
ndn_sd_identity_t*
ndn_sd_find_neigbor(const name_component_t* id);

/**
 * Find a service provider in the neighbor list by searching service ID.
 * @param id. Input. The service ID searched.
 * @param id_size. Input. Size of input service ID.
 * @return pointer to the first service provider's neighbor identity if it exists.
 */
ndn_sd_identity_t*
ndn_sd_find_first_service_provider(const char* id_value, uint32_t id_size);

/**
 * Prepare a Service Discovery Advertisement. This function should be called after setting local services status.
 * @param interest. Output. The prepared advertisement interest.
 */
void
ndn_sd_prepare_advertisement(ndn_interest_t* interest);

/**
 * Prepare a Service Discovery Query. Users should manually sign the output query 
 * interest to obtain a valid signed query interest. 
 * @param interest. Output. The prepared unsigned query interest.
 * @param target. Input. The query target identity.
 * @param service. Input. The query target service.
 * @param params_value. Input. The query parameter buffer (optional)
 * @param params_size. Input. Size of input buffer (optional)
 */
void
ndn_sd_prepare_query(ndn_interest_t* interest, name_component_t* target, ndn_service_t* service,
                     const uint8_t* params_value, uint32_t params_size);

/**
 * Process Service Discovery Advertisement. This function will automatically set and 
 * update local Service Discovery State and is used in receiver side onInterest callback.
 * @param interest. Input. Decoded advertisement interest.
 * @return 0 if there is no error.
 */
int
ndn_sd_on_advertisement_process(const ndn_interest_t* interest);

/**
 * Process Service Discovery Query. This function is used in receiver side onInterest callback.
 * @param interest. Input. Decoded and signature verified query interest.
 * @param response. Output. Prepared query response.
 * @return 0 if there is no error.
 */
int
ndn_sd_on_query_process(const ndn_interest_t* interest, ndn_data_t* response);

/**
 * Process Service Discovery Query's Response. This function will automatically set and 
 * update local Service Discovery State and is used in sender side onData callback.
 * @param response. Input. Decoded and signature verified query response.
 * @return 0 if there is no error.
 */
int
ndn_sd_on_query_response_process(const ndn_data_t * response);

/**
 * Process Service Discovery Query's Timeout. This function will automatically remove query target
 * identity from local neighbor list and is used in sender side onInterestTimeout callback.
 * @param interest. Input. Expired interest.
 * @return 0 if there is no error.
 */
int
ndn_sd_on_query_timeout_process(const ndn_interest_t* interest);

#ifdef __cplusplus
}
#endif

#endif // NDN_APP_SUPPORT_SERVICE_DISCOVERY_H
