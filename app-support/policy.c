/*
 * Copyright (C) 2018-2020
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
#include "pub-sub.h"
#include "../encode/ndn-rule-storage.h"
#include "../encode/key-storage.h"
#include "../ndn-services.h"
#include "policy.h"

#include "stdio.h"

/**
 *      TLV_Type_DataRule
 *      TLV_Length_DataRule
 *      TLV_Value_DataRule
 * 
 *      TLV_Type_KeyRule
 *      TLV_Length_KeyRule
 *      TLV_Value_KeyRule
 * 
 */
void
_on_new_policy(const ps_event_context_t* context, const ps_event_t* event, void* userdata)
{
  (void)userdata;
  NDN_LOG_DEBUG("RECEIVED NEW DATA\n");
  NDN_LOG_DEBUG("Data id: %.*s\n", event->data_id_len, event->data_id);
  NDN_LOG_DEBUG("Data payload length: %d\n", event->payload_len);
  NDN_LOG_DEBUG("Scope: %s\n", context->scope);

  int ret_val = -1;
  uint32_t probe_1, probe_2;
  ndn_decoder_t decoder;
  ndn_trust_schema_rule_t rule;

  uint8_t buffer[218];
  memcpy(buffer, event->payload, event->payload_len);
  decoder_init(&decoder, buffer, event->payload_len);

  ret_val = decoder_get_type(&decoder, &probe_1);
  if (ret_val != NDN_SUCCESS || probe_1 != TLV_POLICY_DATARULE) {
    NDN_LOG_ERROR("policy datarule type not correct, probe_1 = %d\n", probe_1);
    return;
  }

  ret_val = decoder_get_length(&decoder, &probe_1);
  if (ret_val != NDN_SUCCESS) {
    NDN_LOG_ERROR("policy datarule length not correct\n");
    return;
  }

  uint8_t datarule[40], keyrule[40];
  ret_val = decoder_get_raw_buffer_value(&decoder, datarule, probe_1);
  ret_val = decoder_get_type(&decoder, &probe_2);
  ret_val = decoder_get_length(&decoder, &probe_2);
  ret_val = decoder_get_raw_buffer_value(&decoder, keyrule, probe_2);
  ret_val = ndn_trust_schema_rule_from_strings(&rule, (char*)datarule, probe_1, (char*)keyrule, probe_2);
  if (ret_val != NDN_SUCCESS) {
    NDN_LOG_ERROR("constuct trust schema failure, error code is %d\n", ret_val);
    return;
  }
  NDN_LOG_DEBUG("successfully decode trust schema from Pub/Sub payload\n");

  // update or create the "default" rule
  ndn_trust_schema_rule_t* query = ndn_rule_storage_get_rule("default");
  if (query) {
    NDN_LOG_DEBUG("find 'default' rule, update it\n"); 
    ret_val = ndn_trust_schema_pattern_from_string(&query->data_pattern, (char*)datarule, probe_1);
    ret_val = ndn_trust_schema_pattern_from_string(&query->data_pattern, (char*)keyrule, probe_2);
    if (ret_val != 0) {
      NDN_LOG_ERROR("construct trust schema pattern failyre, error code is %d\n", ret_val);
      return;
    }
  }

  else {
    NDN_LOG_DEBUG("no 'default' rule, add 'default' to the rule storage\n");    
    ret_val = ndn_rule_storage_add_rule("default", &rule);
    if (ret_val != 0) {
      NDN_LOG_ERROR("add trust schema failure, error code is %d\n", ret_val);
      return;
    }
  }
}


void
ndn_policy_after_bootstrapping(uint32_t interval)
{
  // adding existing rules to rule storage
  ndn_trust_schema_rule_t schema;
  ndn_trust_schema_rule_from_strings(&schema, cmd_controller_only_rule_data_name, strlen(cmd_controller_only_rule_data_name),
                                     cmd_controller_only_rule_key_name, strlen(cmd_controller_only_rule_key_name));
  ndn_rule_storage_add_rule("controller-only", &schema);
  //NDN_LOG_INFO("subscribe to policy update\n");
  //ps_subscribe_to_content(NDN_SD_POLICY, "", interval, _on_new_policy, NULL); 
}