/*
 * Copyright (C) 2019 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "pub-sub.h"
#include "service-discovery.h"
#include "../ndn-constants.h"
#include "../ndn-services.h"
#include "../encode/key-storage.h"
#include "../encode/wrapper-api.h"
#define ENABLE_NDN_LOG_INFO 1
#define ENABLE_NDN_LOG_DEBUG 1
#define ENABLE_NDN_LOG_ERROR 1
#include "../util/logger.h"
#include "../forwarder/forwarder.h"

#define NDN_PUBSUB_TOPIC_SIZE 10
#define NDN_PUBSUB_IDENTIFIER_SIZE 2
#define NDN_PUBSUB_MAC_TIMEOUT 2

#define PUB  1
#define SUB  2
#define MATCH_SHORT 1
#define MATCH_LONG  0
#define DATA 1
#define CMD 0

/** The struct to keep each topic subscribed.
 */
typedef struct sub_topic {
  /** Service ID
   */
  uint8_t service;
  /** Type of expected Data, can be either CMD or DATA
   */
  bool is_cmd;
  /** Identifier. Should be 0 - 2 NameComponents.
   */
  name_component_t identifier[NDN_PUBSUB_IDENTIFIER_SIZE];
  /** Interval. Time Interval between two Subscription Interest.
   */
  uint32_t interval;
  /** The time to send the next Subscription Interest.
   */
  uint64_t next_interest;
  /** On DATA/CMD publish callback.
   */
  ndn_on_published callback;
  /** User defined data.
   */
  void* userdata;
  /** Decryption Key ID
   */
  uint32_t decryption_key;
} sub_topic_t;

/** The struct to keep each topic published.
 */
typedef struct pub_topic {
  /** Service ID
   */
  uint8_t service;
  /** Type of expected Data, can be either CMD or DATA
   */
  bool is_cmd;
  /** Cache of the lastest published DATA. If the entry is about a subscription record,
   * cache here will not be used.
   */
  uint8_t cache[200];
  /** Cached Data Size.
   */
  uint32_t cache_size;
  /** The timestamp of last update.
   */
  uint64_t last_update_tp;
  /** Decryption Key ID
   */
  uint32_t decryption_key;
} pub_topic_t;

/** The struct to keep registered topics
 */
typedef struct pub_sub_state {
  /** Topic List
   */
  sub_topic_t sub_topics[5];
  /** Topic List
   */
  pub_topic_t pub_topics[5];
  /** Minimal Interval in the Topic List. Currently not used.
   */
  uint32_t min_interval;
  /** Timepoint for the next fetching
   */
  ndn_time_ms_t m_next_send;
} pub_sub_state_t;
uint8_t pkt_encoding_buf[300];

static pub_sub_state_t m_pub_sub_state;
static bool m_has_initialized = false;

int
_on_subscription_interest(const uint8_t* raw_interest, uint32_t interest_size, void* userdata);

/** Helper function to initialize the topic List
 */
void
_ps_topics_init()
{
  for (int i = 0; i < 5; i++) {
    m_pub_sub_state.sub_topics[i].service = NDN_SD_NONE;
    m_pub_sub_state.sub_topics[i].identifier[0].size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    m_pub_sub_state.sub_topics[i].identifier[1].size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    m_pub_sub_state.sub_topics[i].callback = NULL;
    m_pub_sub_state.sub_topics[i].next_interest = 0;

    m_pub_sub_state.pub_topics[i].service = NDN_SD_NONE;
  }
  m_pub_sub_state.m_next_send = 0;
  m_pub_sub_state.min_interval = 1000;
  m_has_initialized = true;
}

/** Helper function to to perform sub Topic matching.
 */
sub_topic_t*
_match_sub_topic(uint8_t service, bool is_cmd, const name_component_t* identifier, uint32_t component_size)
{
  // NDN_LOG_DEBUG("Topic Matching: input_option = %d, compare_option = %d", input_option, compare_option);
  sub_topic_t* entry = NULL;
  for (int i = 0; i < 5; i++) {
    if (m_pub_sub_state.sub_topics[i].service == service && m_pub_sub_state.sub_topics[i].is_cmd == is_cmd) {
      entry = &m_pub_sub_state.sub_topics[i];
    }
  }
  return entry;
}

/** Helper function to to perform pub Topic matching.
 */
pub_topic_t*
_match_pub_topic(uint8_t service, bool is_cmd)
{
  // NDN_LOG_DEBUG("Topic Matching: input_option = %d, compare_option = %d", input_option, compare_option);
  pub_topic_t* entry = NULL;
  for (int i = 0; i < 5; i++) {
    if (m_pub_sub_state.pub_topics[i].service == service && m_pub_sub_state.pub_topics[i].is_cmd == is_cmd) {
      entry = &m_pub_sub_state.pub_topics[i];
    }
  }
  return entry;
}

/** Ontimeout callback to indicating a Subscription Interest timout. Simply logging the timeout event.
 */
void
_on_sub_timeout(void* userdata)
{
  NDN_LOG_INFO("Subscription Interest Timeout");
}

/** OnData callback function to handle incoming content.
 */
void
_on_new_content(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  NDN_LOG_INFO("Fetched New Published Data...");
  sub_topic_t* topic = (sub_topic_t*)userdata;
  // parse Data name
  ndn_name_t data_name;
  uint8_t* content;
  size_t content_size;

  tlv_parse_data(raw_data, data_size, 3,
                 TLV_DATAARG_NAME_PTR, &data_name,
                 TLV_DATAARG_CONTENT_BUF, &content,
                 TLV_DATAARG_CONTENT_SIZE, &content_size);

  // call the on_content callbackclear
  if (topic->callback) {
    int comp_size = 0;
    for (int i = 0; i < 2; i++) {
      if (topic->identifier[i].size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
        comp_size++;
      }
    }
    // get action if it's a command
    // command Data FORMAT: /home/service/CMD/NOTIFY/identifier[0,2]/action
    uint8_t action = 0;
    if (topic->is_cmd) {
      action = data_name.components[data_name.components_size - 2].value[0];
    }
    topic->callback(topic->service, topic->is_cmd, topic->identifier, comp_size,
                    action, content, content_size, topic->userdata);
  }
}

/** Helper function to construct a name for the Interest to fetch subscribted topic content
 */
void
_construct_sub_interest(ndn_name_t* name, sub_topic_t* topic)
{
  ndn_name_init(name);
  // FORMAT: /home-prefix/service/type/identifier[0,2]
  // home prefix
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ndn_name_append_component(name, &storage->self_identity.components[0]);
  ndn_name_append_bytes_component(name, &topic->service, sizeof(topic->service));
  uint8_t type = topic->is_cmd? CMD:DATA;
  ndn_name_append_bytes_component(name, &type, sizeof(type));
  for (int i = 0; i < 2; i++) {
    if (topic->identifier[i].size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      ndn_name_append_component(name, &topic->identifier[i]);
    }
  }
}

/*
 * Helper function to periodically fetch from the Subsribed Topic.
 */
void
_periodic_sub_content_fetching(void *self, size_t param_length, void *param)
{
  (void)self;
  (void)param_length;
  (void)param;
  ndn_time_ms_t now = ndn_time_now_ms();
  if (now < m_pub_sub_state.m_next_send) {
    ndn_msgqueue_post(NULL, _periodic_sub_content_fetching, 0, NULL);
    return;
  }
  m_pub_sub_state.m_next_send = now + m_pub_sub_state.min_interval;
  sub_topic_t* topic = NULL;
  ndn_name_t name;

  // check the table
  for (int i = 0; i < 5; i++) {
    topic = &m_pub_sub_state.sub_topics[i];
    if (topic->service != NDN_SD_NONE && topic->is_cmd == false && now >= topic->next_interest) {
      // send out subscription interest
      _construct_sub_interest(&name, topic);
      size_t used_size = 0;
      tlv_make_interest(pkt_encoding_buf, sizeof(pkt_encoding_buf), &used_size, 4,
                        TLV_INTARG_NAME_PTR, &name,
                        TLV_INTARG_CANBEPREFIX_BOOL, true,
                        TLV_INTARG_MUSTBEFRESH_BOOL, true,
                        TLV_INTARG_LIFETIME_U64, (uint64_t)600);
      int ret = ndn_forwarder_express_interest(pkt_encoding_buf, used_size, _on_new_content, _on_sub_timeout, topic);
      NDN_LOG_INFO("Subscription Interest Sending..., return value %d", ret);

      // update next_interest time
      topic->next_interest = now + topic->interval;
    }
  }

  // register the event to the message queue again with the smallest time period
  ndn_msgqueue_post(NULL, _periodic_sub_content_fetching, 0, NULL);
}

int
_on_subscription_interest(const uint8_t* raw_interest, uint32_t interest_size, void* userdata)
{
  // parse interest
  NDN_LOG_INFO("On Subscription Interest...");
  ndn_interest_t interest;
  ndn_interest_from_block(&interest, raw_interest, interest_size);

  // match topic
  pub_topic_t* topic = (pub_topic_t*)userdata;

  // reply the latest content
  NDN_LOG_INFO("Subscribed Topic Data Publishing...");
  ndn_forwarder_put_data(topic->cache, topic->cache_size);
  return NDN_FWD_STRATEGY_SUPPRESS;
}

int
_on_notification_interest(const uint8_t* raw_interest, uint32_t interest_size, void* userdata)
{
  // FORMAT: /home/service/CMD/NOTIFY/identifier[0,2]/action
  NDN_LOG_INFO("On Notification Interest...");
  ndn_interest_t interest;
  ndn_interest_from_block(&interest, raw_interest, interest_size);

  // check whether identifiers match
  sub_topic_t* topic = (sub_topic_t*)userdata;
  if (topic->identifier[0].size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE
      && name_component_compare(&topic->identifier[0], &interest.name.components[4]) != NDN_SUCCESS) {
    // does not match
    return NDN_FWD_STRATEGY_SUPPRESS;
  }
  if (topic->identifier[1].size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE
      && name_component_compare(&topic->identifier[1], &interest.name.components[5]) != NDN_SUCCESS) {
    // does not match
    return NDN_FWD_STRATEGY_SUPPRESS;
  }

  // send out
  ndn_name_t name;
  ndn_name_init(&name);
  for (int i = 0; i < interest.name.components_size; i++) {
    if (i == 3) {
      continue;
    }
    ndn_name_append_component(&name, &interest.name.components[i]);
  }
  size_t used_size = 0;
  tlv_make_interest(pkt_encoding_buf, sizeof(pkt_encoding_buf), &used_size, 4,
                    TLV_INTARG_NAME_PTR, name,
                    TLV_INTARG_CANBEPREFIX_BOOL, true,
                    TLV_INTARG_MUSTBEFRESH_BOOL, true,
                    TLV_INTARG_LIFETIME_U64, (uint64_t)600);
  int ret = ndn_forwarder_express_interest(pkt_encoding_buf, used_size, _on_new_content, _on_sub_timeout, topic);
  NDN_LOG_INFO("Subscription Interest Sending...");
  return NDN_FWD_STRATEGY_SUPPRESS;
}

void
ps_subscribe_to(uint8_t service, bool is_cmd, const name_component_t* identifier, uint32_t component_size,
                uint32_t interval, ndn_on_published callback, void* userdata)
{
  if (!m_has_initialized)
    _ps_topics_init();

  int ret = 0;
  // find whether the topic has been subscribed already
  sub_topic_t* topic = _match_sub_topic(service, is_cmd, identifier, component_size);
  if (topic) {
    NDN_LOG_DEBUG("ps_subscribe_to: Already Subscribed on the Same Topic. Update this Subscription");
  }
  else {
    for (int i = 0; i < 5; i++) {
      if (m_pub_sub_state.sub_topics[i].service == NDN_SD_NONE) {
        topic = &m_pub_sub_state.sub_topics[i];
      }
    }
    if (topic == NULL) {
      NDN_LOG_DEBUG("ps_subscribe_to: No more space for new subscription. Abort.");
      return;
    }
    topic->service = service;
    topic->is_cmd = is_cmd;
  }

  // update locator
  for (int i = 0; i < 2; i++) {
    if (i < component_size) {
      memcpy(&topic->identifier[i], identifier + i, sizeof(name_component_t));
    }
    else {
      topic->identifier[i].size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    }
  }
  // update interval, callback, and other state
  topic->interval = interval;
  if (topic->interval < m_pub_sub_state.min_interval) {
    m_pub_sub_state.min_interval = topic->interval;
  }
  topic->callback = callback;
  topic->userdata = userdata;
  topic->next_interest = ndn_time_now_ms() + topic->interval;

  // if subscribe to a command topic, register the interest filter to listen to NOTIF for immediate cmd fetch
  // FORMAT: /home-prefix/service/type/NOTIFY/identifier[0,2]
  if (is_cmd) {
    ndn_name_t name;
    ndn_name_init(&name);
    ndn_key_storage_t* storage = ndn_key_storage_get_instance();
    ndn_name_append_component(&name, &storage->self_identity.components[0]);
    ndn_name_append_bytes_component(&name, &topic->service, sizeof(topic->service));
    uint8_t type = topic->is_cmd? CMD:DATA;
    ndn_name_append_bytes_component(&name, &type, sizeof(type));
    ndn_name_append_string_component(&name, "NOTIFY", strlen("NOTIFY"));
    ndn_forwarder_register_name_prefix(&name, _on_notification_interest, topic);
  }
  return;
}

void
ps_after_bootstrapping()
{
  if (!m_has_initialized)
    _ps_topics_init();
  _periodic_sub_content_fetching(NULL, 0, NULL);
}

void
ps_publish_content(uint8_t service, uint8_t* payload, uint32_t payload_len)
{
  if (!m_has_initialized)
    _ps_topics_init();

  int ret = 0;

  // Prefix FORMAT: /home/service/DATA
  ndn_name_t name;
  ndn_name_init(&name);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ndn_name_append_component(&name, &storage->self_identity.components[0]);
  ndn_name_append_bytes_component(&name, &service, sizeof(service));
  uint8_t type = DATA;
  ndn_name_append_bytes_component(&name, &type, 1);

  // published on this topic before? update the cache
  pub_topic_t* topic = NULL;
  topic = _match_pub_topic(service, false);
  if (topic) {
    NDN_LOG_DEBUG("_publish_content: Found a topic published before. Update content.");
  }
  else {
    for (int i = 0; i < 5; i++) {
      if (m_pub_sub_state.pub_topics[i].service == NDN_SD_NONE) {
        topic = &m_pub_sub_state.pub_topics[i];
      }
    }
    NDN_LOG_DEBUG("_publish_content: No availble topic, will drop the oldest pub topic.");
    if (topic == NULL) {
      uint64_t min_last_tp = m_pub_sub_state.pub_topics[0].last_update_tp;
      int index = -1;
      for (int i = 1; i < 5; i++) {
        if (m_pub_sub_state.pub_topics[i].last_update_tp < min_last_tp) {
          min_last_tp = m_pub_sub_state.pub_topics[i].last_update_tp;
          index = i;
        }
      }
      topic = &m_pub_sub_state.pub_topics[index];
      // TODO: unregister the prefix registered by the old topic
      // register the new prefix
      ndn_forwarder_register_name_prefix(&name, _on_subscription_interest, topic);
    }
    topic->service = service;
    topic->is_cmd = false;
  }
  topic->last_update_tp = ndn_time_now_ms();
  // Append the last several component to the Data name
  // Data name FORMAT: /home/service/DATA/room/device-id/tp
  ndn_name_append_component(&name, &storage->self_identity.components[1]);
  ndn_name_append_component(&name, &storage->self_identity.components[2]);
  // TODO: currently I appended timestamp. Further discussion is needed.
  ndn_name_append_bytes_component(&name, (uint8_t*)&topic->last_update_tp, sizeof(ndn_time_ms_t));
  memset(topic->cache, 0, sizeof(topic->cache));
  ret = tlv_make_data(topic->cache, sizeof(topic->cache), &topic->cache_size, 6,
                      TLV_DATAARG_NAME_PTR, &name,
                      TLV_DATAARG_CONTENT_BUF, payload,
                      TLV_DATAARG_CONTENT_SIZE, payload_len,
                      TLV_DATAARG_SIGTYPE_U8, NDN_SIG_TYPE_ECDSA_SHA256,
                      TLV_DATAARG_IDENTITYNAME_PTR, &storage->self_identity,
                      TLV_DATAARG_SIGKEY_PTR, &storage->self_identity_key);
  NDN_LOG_DEBUG("_ps_publish: Data Encoding...");
}

void
ps_publish_command(uint8_t service, uint8_t action, const name_component_t* identifier, uint32_t component_size,
                   uint8_t* payload, uint32_t payload_len)
{
  if (!m_has_initialized)
    _ps_topics_init();

  int ret = 0;
  // Prefix FORMAT: /home/service/CMD
  ndn_name_t name;
  ndn_name_init(&name);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ndn_name_append_component(&name, &storage->self_identity.components[0]);
  ndn_name_append_bytes_component(&name, &service, sizeof(service));
  uint8_t type = CMD;
  ndn_name_append_bytes_component(&name, &type, 1);

  // published on this topic before? update the cache
  pub_topic_t* topic = NULL;
  topic = _match_pub_topic(service, false);
  if (topic) {
    NDN_LOG_DEBUG("_publish_command: Found a topic published before. Update content.");
  }
  else {
    for (int i = 0; i < 5; i++) {
      if (m_pub_sub_state.pub_topics[i].service == NDN_SD_NONE) {
        topic = &m_pub_sub_state.pub_topics[i];
      }
    }
    NDN_LOG_DEBUG("_publish_command: No availble topic, will drop the oldest pub topic.");
    if (topic == NULL) {
      uint64_t min_last_tp = m_pub_sub_state.pub_topics[0].last_update_tp;
      int index = -1;
      for (int i = 1; i < 5; i++) {
        if (m_pub_sub_state.pub_topics[i].last_update_tp < min_last_tp) {
          min_last_tp = m_pub_sub_state.pub_topics[i].last_update_tp;
          index = i;
        }
      }
      topic = &m_pub_sub_state.pub_topics[index];
      // TODO: unregister the prefix registered by the old topic
      // register the new prefix
      ndn_forwarder_register_name_prefix(&name, _on_subscription_interest, topic);
    }
    topic->service = service;
    topic->is_cmd = false;
  }
  topic->last_update_tp = ndn_time_now_ms();
  memset(topic->cache, 0, sizeof(topic->cache));

  // Append the last several component to the Data name
  // Data name FORMAT: /home/service/CMD/identifier[0,2]/action
  for (int i = 0; i < component_size; i++) {
    ndn_name_append_component(&name, identifier + i);
  }
  ndn_name_append_bytes_component(&name, &action, sizeof(action));
  // TODO: currently I appended timestamp. Further discussion is needed.
  ndn_time_ms_t tp = ndn_time_now_ms();
  ndn_name_append_bytes_component(&name, (uint8_t*)&tp, sizeof(ndn_time_ms_t));
  ret = tlv_make_data(topic->cache, sizeof(topic->cache), &topic->cache_size, 6,
                      TLV_DATAARG_NAME_PTR, &name,
                      TLV_DATAARG_CONTENT_BUF, payload,
                      TLV_DATAARG_CONTENT_SIZE, payload_len,
                      TLV_DATAARG_SIGTYPE_U8, NDN_SIG_TYPE_ECDSA_SHA256,
                      TLV_DATAARG_IDENTITYNAME_PTR, &storage->self_identity,
                      TLV_DATAARG_SIGKEY_PTR, &storage->self_identity_key);
  NDN_LOG_DEBUG("_publish_command: Data Encoding...");

  // express the /Notify Interest
  // FORMAT: /home/service/CMD/NOTIFY/identifier[0,2]/action
  ndn_name_init(&name);
  ndn_name_append_component(&name, &storage->self_identity.components[0]);
  ndn_name_append_bytes_component(&name, &service, sizeof(service));
  ndn_name_append_bytes_component(&name, &type, 1);
  ndn_name_append_string_component(&name, "NOTIFY", strlen("NOTIFY"));
  for (int i = 0; i < component_size; i++) {
    ndn_name_append_component(&name, identifier + i);
  }
  ndn_name_append_bytes_component(&name, &action, sizeof(action));
  ndn_name_append_bytes_component(&name, (uint8_t*)&tp, sizeof(ndn_time_ms_t));

  // send out the notification Interest
  NDN_LOG_INFO("_publish_command: Send notification Interest for new command...");
  uint8_t buffer[100];
  uint32_t buffer_length = 0;
  tlv_make_interest(buffer, sizeof(buffer), &buffer_length, 4,
                    TLV_INTARG_NAME_PTR, &name,
                    TLV_INTARG_CANBEPREFIX_BOOL, true,
                    TLV_INTARG_MUSTBEFRESH_BOOL, true,
                    TLV_INTARG_LIFETIME_U64, (uint64_t)600);
  ndn_forwarder_express_interest(buffer, buffer_length, _on_new_content, _on_sub_timeout, NULL);
}
