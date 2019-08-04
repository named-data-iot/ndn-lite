/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
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

const static uint32_t sd_adv_interval = 3600;

/**
 * The structure to represent a NDN service.
 */
typedef struct ndn_service {
  /**
   * a bit vector showing: 1. whether to broadcast (leftmost bit)
   *                       2. the state of the service (rightmost three bits)
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
   * The locator name of the device
   */
  const name_component_t* device_locator[5];
  uint8_t device_locator_size;
  /**
   * Device IDs
   */
  ndn_service_t services[10];
} sd_self_state;

/**
 * The structure to keep the cached service information in the system
 */
typedef struct sd_sys_state {
  ndn_name_t cached_services[NDN_SD_SERVICES_SIZE];
  uint32_t freshness_period[NDN_SD_SERVICES_SIZE];
} sd_sys_state_t;

/**
 * Load a device's services into the state.
 * @param dev_identity_name. Input. The name of a device in the format of
 *   /[home-prefix]/[device-locator], a device-locator could be "/bedroom/sensor1" or "/front-door-lock"
 */
void
sd_init_self_services(const ndn_name_t* dev_identity_name);

/**
 * Register the prefixes with corresponding onInterest, onData callbacks.
 * Should be called ONLY ONCE after the service discovery state is initialized.
 */
void
sd_listen();

/**
 * Express an Interest packet to advertise one's own services.
 */
void
sd_start_adv_self_services();

/**
 * Query interested services from the system controller.
 * Usually used at the end of the security bootstrapping.
 * @param service_id. Input. The service ID that the device is interested in.
 */
void
sd_query_sys_services(uint8_t service_id);

/**
 * Express an Interest packet to query the SPs for the service.
 * @param service_id. Input. The service to be queried.
 * @param is_any. Input. If is true, query one SP that can provide the service.
 *   If is false, query all the SPs that can provide the service.
 */
void
sd_query_service(uint8_t service_id, ndn_name_t granularity, bool is_any);


// /**
//  * Init a Service Discovery State structure.
//  * @param home_prefix. Input. The network home prefix to configure the state manager.
//  * @param self_id. Input. The local state manager identity.
//  */
// void
// ndn_sd_init(const ndn_name_t* home_prefix, const name_component_t* self_id);

// /**
//  * Get a pointer to a NDN service by searching its NDN service ID.
//  * @param id_value. Input. Service ID buffer.
//  * @param id_size. Input. Size of input service ID.
//  * @return pointer to the NDN service if it exists.
//  */
// ndn_service_t*
// ndn_sd_register_get_self_service(const char* id_value, uint32_t id_size);

// /**
//  * Set service status of a NDN service.
//  * @param service. Input. The NDN service whose service status will be set.
//  * @param status. Input. Service status value.
//  * @return 0 if there is no error.
//  */
// static inline int
// ndn_sd_set_service_status(ndn_service_t* service, uint8_t status)
// {
//   service->status = status;
//   return 0;
// }

// /**
//  * Find a neighbor in the neighbor list by searching its identity.
//  * @param id. Input. The neighbor identity searched.
//  * @return pointer to the neighbor identity if it exists.
//  */
// ndn_sd_identity_t*
// ndn_sd_find_neigbor(const name_component_t* id);

// /**
//  * Find a service provider in the neighbor list by searching service ID.
//  * @param id. Input. The service ID searched.
//  * @param id_size. Input. Size of input service ID.
//  * @return pointer to the first service provider's neighbor identity if it exists.
//  */
// ndn_sd_identity_t*
// ndn_sd_find_first_service_provider(const char* id_value, uint32_t id_size);

// /**
//  * Prepare a Service Discovery Advertisement. This function should be called after setting local services status.
//  * @param interest. Output. The prepared advertisement interest.
//  */
// void
// ndn_sd_prepare_advertisement(ndn_interest_t* interest);

// /**
//  * Prepare a Service Discovery Query. Users should manually sign the output query
//  * interest to obtain a valid signed query interest.
//  * @param interest. Output. The prepared unsigned query interest.
//  * @param target. Input. The query target identity.
//  * @param service. Input. The query target service.
//  * @param params_value. Input. The query parameter buffer (optional)
//  * @param params_size. Input. Size of input buffer (optional)
//  */
// void
// ndn_sd_prepare_query(ndn_interest_t* interest, name_component_t* target, ndn_service_t* service,
//                      const uint8_t* params_value, uint32_t params_size);

// /**
//  * Process Service Discovery Advertisement. This function will automatically set and
//  * update local Service Discovery State and is used in receiver side onInterest callback.
//  * @param interest. Input. Decoded advertisement interest.
//  * @return 0 if there is no error.
//  */
// int
// ndn_sd_on_advertisement_process(const ndn_interest_t* interest);

// /**
//  * Process Service Discovery Query. This function is used in receiver side onInterest callback.
//  * @param interest. Input. Decoded and signature verified query interest.
//  * @param response. Output. Prepared query response.
//  * @return 0 if there is no error.
//  */
// int
// ndn_sd_on_query_process(const ndn_interest_t* interest, ndn_data_t* response);

// /**
//  * Process Service Discovery Query's Response. This function will automatically set and
//  * update local Service Discovery State and is used in sender side onData callback.
//  * @param response. Input. Decoded and signature verified query response.
//  * @return 0 if there is no error.
//  */
// int
// ndn_sd_on_query_response_process(const ndn_data_t * response);

// /**
//  * Process Service Discovery Query's Timeout. This function will automatically remove query target
//  * identity from local neighbor list and is used in sender side onInterestTimeout callback.
//  * @param interest. Input. Expired interest.
//  * @return 0 if there is no error.
//  */
// int
// ndn_sd_on_query_timeout_process(const ndn_interest_t* interest);

#ifdef __cplusplus
}
#endif

#endif // NDN_APP_SUPPORT_SERVICE_DISCOVERY_H
