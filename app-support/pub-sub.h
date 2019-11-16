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
 * This function will register a event that periodically send an Interest to the name prefix and fetch data.
 *
 * @unsolved 1. How to decide the frequency of Interest sending? -- solved
 * @unsolved 2. How to automatically do schematized trust verification? -- solved
 *              A solution is to automatically subscribe to a topic, like /home/trust_schema, and fetch the trust schema
 *              for pkt verification
 * @unsolved 3. How to automatically apply access control, i.e., decrypt the content published -- solved
 *
 * Example: each device can subscribe to CONTROL, device's own prefix, SCHEMA, to obtain the new configuration to verify other's commands
 * each device can subscribe to AC, device's service, EKEY, to obtain the encryption key to encrypt their content published
 */
void
ps_subscribe_to(uint8_t service, bool is_cmd, const name_component_t* identifier, uint32_t component_size,
                uint32_t interval, ndn_on_published callback, void* userdata);

void
ps_after_bootstrapping();

/** publish
 * This function will publish data to a content repo.
 * @param name_prefix. The topic to publish.
 * @param content. The content to publish.
 *
 * @unsolved 1. How to cooperate an external repo?
 * @unsolved 2. How to automatically do packet generation? i.e.: Data name, Signing Key -- solved
 * @unsolved 3. How to automatically apply access control, i.e., Encrypt the content using proper key -- solved
 *
 * Example: temp sensor can publish to: TEMP, bedroom, READ, "37.5 c degree" to publish temp data under /home/TEMP/bedroom/READ
 * controller can publish to: AC, TEMP, EKEY, "fetch from controller for new keys" to distribute new encryption keys
 */
void
ps_publish_content(uint8_t service, uint8_t* payload, uint32_t payload_len);

void
ps_publish_command(uint8_t service, uint8_t action, const name_component_t* identifier, uint32_t component_size,
                   uint8_t* payload, uint32_t payload_len);

#ifdef __cplusplus
}
#endif

#endif /* NDN_APP_SUPPORT_PUB_SUB_H */