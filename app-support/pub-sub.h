/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_APP_SUPPORT_PUB_SUB_H
#define NDN_APP_SUPPORT_PUB_SUB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include "../encode/name-component.h"

/** Pub/Sub Spec
 * Publish content:
 *  1. register a prefix for the newly published content Data packet.
 *  2. reply the Data packet when there is an Interest packet asking for the content.
 *  Content Data format:
 *    Name: /[home-prefix]/[service-id]/DATA/[room]/[device-id]/[content-id]/[timestamp]
 *    Content: content payload
 *    Signature: Signed by device's identity key (an ECC private key certified by the controller)
 *  E.g., /alice-home/NDN_SD_LED/DATA/bedroom/dev-1/dev-state/1577579642303, "WORKING", Sig
 *  E.g., /alice-home/NDN_SD_TEMP/DATA/bedroom/dev-2/cur-temp/1577579695179, "72F", Sig
 *
 * Publish command:
 *  1. register a prefix for the newly published command Data packet
 *  2. send out a notification Interest packet to the IoT system
 *  3. reply the Data packet when there is an Interest packet asking for the command.
 *  Notification Interest format:
 *    Name: /[home-prefix]/[service-id]/CMD/NOTIFY/[room]?/[device-id]?/[command-id]/[timestamp]
 *  Command Data format:
 *    Name: /[home-prefix]/[service-id]/CMD/[room]?/[device-id]?/[command-id]/[timestamp]
 *    Content: command parameters
 *    Signature: Signed by device's identity key (an ECC private key certified by the controller)
 *  E.g., /alice-home/NDN_SD_LED/CMD/bedroom/turn-on/1577579642303, "", Sig
 *  E.g., /alice-home/NDN_SD_AC/CMD/set-temp/1577579642303, "72F", Sig
 */

#define NDN_PUBSUB_IDENTIFIER_SIZE 2

typedef struct ps_event_context {
  uint8_t service;
  char scope[50];
} ps_event_context_t;

typedef struct ps_event {
  const uint8_t* data_id;
  uint32_t data_id_len;
  const uint8_t* payload;
  uint32_t payload_len;
} ps_event_t;

/** on new data/command callback
 * @param service. The service where data/command is published under
 * @param is_cmd. Whether what is newly published is a command
 * @param scope. The name components that indicate the content publisher or command effect scope.
 *    E.g., a command with identifier /bedroom is to command devices under /bedroom.
 *    E.g., a command with no identifiers is to command all devices in the local IoT system.
 *    E.g., a data with identifier /bedroom/device-1 is a piece of content published by this device.
 * @param identifiers_size. The number of identifier components.
 *    Can be zero when is_cmd = true.
 * @param cmd_or_content_id. cmd_or_content_id is either a command id or a data content id.
 *    When is_cmd = true, cmd_or_content_id is command id.
 *    E.g., a string like "SET-TEMP", "TURN-ON" or bytes defined by app protocols.
 *    When is_cmd = false, cmd_or_content_id is content id.
 *    E.g., a string like "BATTERY", "STATE", or bytes defined by app protocols.
 * @param cmd_or_content_id_len. The size of cmd_or_content_id.
 * @param payload. The content of newly published data/command.
 *    E.g., content can keep the data payload or command parameters
 * @param payload_len. The size of content.
 * @param userdata. The userdata that the developer want to pass to the callback function.
 */
typedef void (*ps_on_published)(const ps_event_context_t* context, const ps_event_t* event, void* userdata);
typedef ps_on_published ps_on_content_published;
typedef ps_on_published ps_on_command_published;

void
ps_after_bootstrapping();

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
ps_subscribe_to_content(uint8_t service, const char* scope,
                        uint32_t interval, ps_on_content_published callback, void* userdata);

void
ps_subscribe_to_command(uint8_t service, const char* scope, ps_on_command_published callback, void* userdata);

/** publish data
 * This function will publish data to a content repo.
 * Data format: /home-prefix/service/DATA/my-identifiers/timestamp
 * @TODO: for now I added a timestamp after Data name. Need more discussion, e.g., use nonce? sequence?
 * @TODO: for now I used a default freshness period of the data. Need more discussion, e.g., user-specified?
 */
void
ps_publish_content(uint8_t service, const ps_event_t* event);

/** publish command to the target scope
 * This function will publish command to a content repo and send out a notification Interest.
 * Cmd Notification Interest Format: /home-prefix/service/NOTIFY/CMD/identifier[0,2]/action
 * Data format: /home-prefix/service/CMD/my-identifiers/timestamp
 * @TODO: for now I added a timestamp after Data name, which need more discussion, e.g., use nonce? sequence?
 * @TODO: for now I used a default freshness period of the data. Need more discussion, e.g., user-specified?
 */
void
ps_publish_command(uint8_t service, const char* scope, const ps_event_t* event);

#ifdef __cplusplus
}
#endif

#endif /* NDN_APP_SUPPORT_PUB_SUB_H */
