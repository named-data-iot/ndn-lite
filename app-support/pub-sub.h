/*
 * Copyright (C) 2019 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */


#ifndef NDN_APP_SUPPORT_PUB_SUB_H
#define NDN_APP_SUPPORT_PUB_SUB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include "../encode/name-component.h"

typedef int (*ndn_on_published)(uint8_t service, bool is_cmd,
                                const name_component_t* identifier, uint32_t component_size,
                                uint8_t action, const uint8_t* content, uint32_t content_len,
                                void* userdata);

/** subscribe
 * If is not cmd, this function will register a event that periodically send an Interest to the name
 * prefix and fetch data.
 * Subscription Interest Format: /home-prefix/service/DATA/identifier[0,2],MustBeFresh,CanBePrefix.
 *
 * If is cmd, this function will register a Interest filter /home-prefix/service/CMD and listen to
 * notification on new CMD content.
 * Once there is a comming notification and the identifiers is under subscribed identifiers, an
 * Interest will be sent to fetch the new CMD.
 * Cmd Notification Interest Format: /home/service/CMD/NOTIFY/identifier[0,2]/action
 * Cmd fetching Interest Format: /home/service/CMD/identifier[0,2]/action
 */
void
ps_subscribe_to(uint8_t service, bool is_cmd,
                const name_component_t* identifier, uint32_t component_size,
                uint32_t interval, ndn_on_published callback, void* userdata);

void
ps_after_bootstrapping();

/** publish data
 * This function will publish data to a content repo.
 * Data format: /home-prefix/service/DATA/my-identifiers/timestamp
 * @TODO: for now I added a timestamp after Data name. Need more discussion, e.g., use nonce? sequence?
 * @TODO: for now I used a default freshness period of the data. Need more discussion, e.g., user-specified?
 */
void
ps_publish_content(uint8_t service, uint8_t* payload, uint32_t payload_len);

/** publish command to the target scope
 * This function will publish command to a content repo and send out a notification Interest.
 * Cmd Notification Interest Format: /home-prefix/service/CMD/NOTIFY/identifier[0,2]/action
 * Data format: /home-prefix/service/CMD/my-identifiers/timestamp
 * @TODO: for now I added a timestamp after Data name, which need more discussion, e.g., use nonce? sequence?
 * @TODO: for now I used a default freshness period of the data. Need more discussion, e.g., user-specified?
 */
void
ps_publish_command(uint8_t service, uint8_t action,
                   const name_component_t* identifier, uint32_t component_size,
                   uint8_t* payload, uint32_t payload_len);

#ifdef __cplusplus
}
#endif

#endif /* NDN_APP_SUPPORT_PUB_SUB_H */
