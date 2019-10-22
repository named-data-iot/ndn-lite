/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "pub-sub.h"
#include "service-discovery.h"
#include "../encode/key-storage.h"
#include "../encode/wrapper-api.h"

#define NDN_PUBSUB_TOPIC_SIZE 10
#define NDN_PUBSUB_IDENTIFIER_SIZE 2
#define NDN_PUBSUB_MAC_TIMEOUT 2

#define PUB  1
#define SUB  2
#define MATCH_SHORT 1
#define MATCH_LONG  0

/*
 * The struct to keep each topic subscribed.
 */
typedef struct topic {
  /*
   * Service Code
   */
  uint8_t service;
  /*
   * Identifier. Should be 0 - 2 NameComponents.
   */
  name_component_t identifier[NDN_PUBSUB_IDENTIFIER_SIZE];
  /*
   * Identifier Size. Should be 0 - 2.
   */
  uint32_t identifier_size;
  /*
   * Interval. Time Interval between two Subscription Interest.
   */
  uint32_t interval; // the time interval between two Interests
  /*
   * The time to send the next Subscription Interest.
   */
  uint64_t next_interest;
  /*
   * On DATA/CMD publish callback.
   */
  ndn_on_published callback;
  /*
   * The entry is a subscription record or not.
   */
  uint8_t is_sub;
  /*
   * Type of expected Data, can be either CMD or DATA
   */
  uint8_t type;

  /*
   * Cache of the lastest published DATA. If the entry is about a subscription record,
   * cache here will not be used.
   */
  uint8_t cache[200];
  /*
   * Cached Data Size.
   */
  uint32_t cache_size;
} topic_t;

/*
 * The struct to keep registered topics
 */
typedef struct sub_topics {
  /*
   * Topic List
   */
  topic_t topics[NDN_PUBSUB_TOPIC_SIZE];
  /*
   * Minimal Interval in the Topic List. Currently not used.
   */
  uint32_t min_interval;
} sub_topics_t;

static sub_topics_t m_sub_state;
static bool m_has_initialized = false;

int
_on_subscription_interest(const uint8_t* raw_interest, uint32_t interest_size, void* userdata);
int
_on_notification_interest(const uint8_t* raw_interest, uint32_t interest_size, void* userdata);

/*
 * Helper funciton to initialize the Topic List
 */
void
_ps_topics_init()
{
  for (int i = 0; i < NDN_PUBSUB_TOPIC_SIZE; i++) {
    m_sub_state.topics[i].identifier_size = NDN_FWD_INVALID_NAME_SIZE;
    m_sub_state.topics[i].callback = NULL;
    m_sub_state.topics[i].next_interest = 0;
    m_sub_state.topics[i].is_sub = 0;
  }
  m_has_initialized = true;
}

/*
 * Helper funciton to construct a partial Name. Service Code is the last NameComponent.
 */
void
_service_name_construction(ndn_name_t* name, uint8_t service)
{
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  name_component_t* home_prefix = &storage->self_identity.components[0];
  
  ndn_name_append_component(name, home_prefix);
  ndn_name_append_bytes_component(name, &service, sizeof(service));
}

/*
 * Helper funciton to construct a partial Name. Append the Identifier to the input Name.
 */
void
_identifier_name_construction(ndn_name_t* name, const name_component_t* identifier, uint32_t component_size)
{
  if(identifier && component_size > 0)
    for (int i = 0; i < component_size; i++)
      ndn_name_append_component(name, &identifier[i]);
}

/*
 * Helper funciton to register the notification prefix. The prefix is in the domain of corresponding Service.
 */
_notification_prefix_register(ndn_name_t* name, uint8_t service, topic_t* entry)
{
  
  _service_name_construction(name, service);
  ndn_name_append_string_component(name, "NOTIFY", strlen("NOTIFY"));
  printf("registered name: ");ndn_name_print(name);putchar('\n');
  ndn_forwarder_register_name_prefix(name, _on_notification_interest, entry);
}

/*
 * Helper funciton to construct a Name. register_prefix is an option whether register the coresponding CMD 
 * or DATA prefix before appending the Identifier.
 */
void
_name_construction(ndn_name_t* name, uint8_t type, uint8_t service,
                   const name_component_t* identifier, uint32_t component_size,
                   uint8_t register_prefix)
{
  _service_name_construction(name, service);
  
  if (type == DATA)
    ndn_name_append_string_component(name, "DATA", strlen("DATA"));
  else if (type == CMD)
    ndn_name_append_string_component(name, "CMD", strlen("CMD"));
  else return;

  if (register_prefix && type == DATA) {
     ndn_forwarder_register_name_prefix(name, _on_subscription_interest, NULL);
     printf("registered name: ");ndn_name_print(name);putchar('\n');
  }

  _identifier_name_construction(name, identifier, component_size);

  printf("_name_construction: ");ndn_name_print(name);putchar('\n');

}

/*
 * Helper funciton to to perform Topic matching. input_option refers to type of Topic records to match, 
 * can be SUB or PUB. compare_option indicates the expected returned Topic Name is shorter/longer than 
 * the input Name.  
 */
topic_t*
_match_topic(const ndn_name_t* name, uint8_t input_option, uint8_t compare_option)
{
  printf("_match_topic, in_coming name = ");ndn_name_print(name);putchar('\n');

  ndn_name_t prefix;
  for (int i = 0; i < NDN_PUBSUB_TOPIC_SIZE; i++) 
  {
    topic_t* entry = &m_sub_state.topics[i];
    if (entry->next_interest && entry->is_sub == input_option)
    {
      ndn_name_init(&prefix);
      _name_construction(&prefix, entry->type, entry->service, 
                          entry->identifier, entry->identifier_size, 0);
      
      // compare against data_name
      printf("_match_topic, to compare prefix = ");ndn_name_print(&prefix);putchar('\n');
       
      int ret = -1;
      if (compare_option)
        ret = ndn_name_is_prefix_of(&prefix, name);
      else 
        ret = ndn_name_is_prefix_of(name, &prefix);
      
      if (!ret) {
        printf("_match_topic, prefix matched!\n");
        return entry;
      }
    }
  }
  return NULL;
}

/*
 * Helper funciton to allocate a Topic slot. Would return nullptr if Topic List is full.
 */
topic_t*
_allocate_topic(ndn_on_published callback, uint8_t service, uint32_t frequency,
                name_component_t* identifier, uint32_t component_size,
                uint8_t is_sub, uint8_t type)
{
  for (int i = 0; i < NDN_PUBSUB_TOPIC_SIZE; i++) {
    topic_t* entry = &m_sub_state.topics[i];
    if (entry->is_sub == 0) {
      entry->callback = callback;
      entry->interval = frequency;
      entry->service = service;
      entry->is_sub = is_sub;
      entry->type = type;
      //immediate send
      entry->next_interest = ndn_time_now_ms();
      entry->identifier_size = 0;
      if (identifier && component_size > 0) {
        for (int j = 0; j < (NDN_PUBSUB_IDENTIFIER_SIZE < component_size ? 
                             NDN_PUBSUB_IDENTIFIER_SIZE : component_size); j++) {
          entry->identifier[j] = identifier[j];
          entry->identifier_size++;
        }
      }
      printf("_allocate_topic: got one!\n");
      return entry;
    }
  }
  return NULL;
}

/*
 * Helper funciton to indicating a Subscription Interest timout. Simply logging the timeout event.
 */
void
_on_sub_timeout(void* userdata)
{
  printf("_on_sub_timeout: remove the entry\n");
}

/*
 * Helper funciton to handle incoming content.
 */
void
_on_new_content(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse Data name
  ndn_name_t data_name;
  uint8_t* content;
  size_t content_size;

  tlv_parse_data(raw_data, data_size, 3, 
                 TLV_DATAARG_NAME_PTR, &data_name,
                 TLV_DATAARG_CONTENT_BUF, &content,
                 TLV_DATAARG_CONTENT_SIZE, &content_size);
  
  // match the subscription topic
  topic_t* entry = _match_topic(&data_name, SUB, MATCH_SHORT);
  if (!entry) {
    printf("_on_new_content: no matching topic, discard\n");
    return;
  } 

  printf("_on_new_content: in coming\n");

  // call the on_content callbackclear
  if (entry->callback)
    entry->callback(entry->service, 0, entry->identifier, entry->identifier_size, 
                    content, content_size);
}

/*
 * Helper funciton to express the Subscription Interest.
 */
void
_go_fetching(ndn_name_t* name, topic_t* entry)
{
  _name_construction(name, entry->type, entry->service, entry->identifier,
                     entry->identifier_size, 0);
  tlv_make_interest(entry->cache, sizeof(entry->cache), &entry->cache_size, 4,
                      TLV_INTARG_NAME_PTR, name,
                      TLV_INTARG_CANBEPREFIX_BOOL, true,
                      TLV_INTARG_MUSTBEFRESH_BOOL, true,
                      TLV_INTARG_LIFETIME_U64, (uint64_t)600);

  int ret = ndn_forwarder_express_interest(entry->cache, 
                                           entry->cache_size,
                                           _on_new_content, _on_sub_timeout, entry);
  
  printf("_go_fetching: ");
  ndn_name_print(name);putchar('\n');
}

/*
 * Helper funciton to periodically fetch from the Subsribed Topic.
 */
void
_periodic_data_fetching(void *self, size_t param_length, void *param)
{
  (void)self;(void)param_length;(void)param;
  ndn_time_ms_t now = ndn_time_now_ms();
  ndn_name_t name;
  ndn_name_init(&name);

  // check the table
  for (int i = 0; i < NDN_PUBSUB_TOPIC_SIZE; i++) {
    topic_t* entry = &m_sub_state.topics[i];
    if (entry->is_sub == SUB && entry->type == DATA)
    {
      if (now >= entry->next_interest)
      {
        _go_fetching(&name, entry);
        entry->next_interest = now + entry->interval;
      }
    }
  }

  // register the event to the message queue again with the smallest time period
  ndn_msgqueue_post(NULL, _periodic_data_fetching, 0, NULL);
}

int
_on_subscription_interest(const uint8_t* raw_interest, uint32_t interest_size, void* userdata)
{
  // parse interest
  printf("_on_subscription_interest\n");
  ndn_name_t interest_name;
  tlv_parse_interest(raw_interest, interest_size, 1, 
                     TLV_INTARG_NAME_PTR, &interest_name);
                     
  // match topic
  topic_t* entry = _match_topic(&interest_name, PUB, MATCH_LONG);

  // reply the latest content
  if (entry)
  {
    printf("_on_subscription_interest: put data\n");
    ndn_forwarder_put_data(entry->cache, entry->cache_size);
  }
  return NDN_FWD_STRATEGY_MULTICAST;
}

void
_ps_publish(uint8_t service, uint8_t type, const name_component_t* identifier, uint32_t component_size,
            uint8_t* info, uint32_t info_len)
{
  if (!m_has_initialized)
    _ps_topics_init();
  
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  name_component_t* home_prefix = &storage->self_identity.components[0];

  int ret = 0;
  ndn_name_t name;
  ndn_name_init(&name);
  _name_construction(&name, type, service, identifier, component_size, 1);

  // addtional name construction for command publish
  if (type == CMD)
    ndn_name_append_bytes_component(&name, info, info_len);

  // published on this topic before? update the cache
  topic_t* entry = NULL;
  if (type == DATA) {
    entry = _match_topic(&name, PUB, MATCH_SHORT);
    if (entry) {
      printf("_ps_publish with update: data name:\n");ndn_name_print(&name);putchar('\n');
      return;
    }
  }

  entry = _allocate_topic(NULL, service, 0, identifier, component_size, PUB, type);
  if (!entry) {
    printf("_ps_publish: no available entry\n");
    return;
  }

  ret = tlv_make_data(entry->cache, sizeof(entry->cache), &entry->cache_size, 6,
                      TLV_DATAARG_NAME_PTR, &name,
                      TLV_DATAARG_CONTENT_BUF, info,
                      TLV_DATAARG_CONTENT_SIZE, info_len,
                      TLV_DATAARG_SIGTYPE_U8, NDN_SIG_TYPE_ECDSA_SHA256,
                      TLV_DATAARG_IDENTITYNAME_PTR, &storage->self_identity,
                      TLV_DATAARG_SIGKEY_PTR, &storage->self_identity_key);
  printf("make data\n");
}

void
_notify(uint8_t service, const name_component_t* identifier, uint32_t component_size)
{
  // /home/TEMP/NOTIFY/identfier
  ndn_name_t name;
  ndn_name_init(&name);
  _service_name_construction(&name, service);
  ndn_name_append_string_component(&name, "NOTIFY", strlen("NOTIFY"));

  printf("_notify: ");ndn_name_print(&name);putchar('\n');

  uint8_t buffer[100];
  uint32_t buffer_length = 0;
  tlv_make_interest(buffer, sizeof(buffer), &buffer_length, 4,
                           TLV_INTARG_NAME_PTR, &name,
                           TLV_INTARG_CANBEPREFIX_BOOL, true,
                           TLV_INTARG_MUSTBEFRESH_BOOL, true,
                           TLV_INTARG_LIFETIME_U64, (uint64_t)600);

  ndn_forwarder_express_interest(buffer, buffer_length,
                                 _on_new_content, _on_sub_timeout, NULL);
}


int
_on_notification_interest(const uint8_t* raw_interest, uint32_t interest_size, void* userdata)
{
  printf("on_notification\n");
  
  // find the /<service>/CMD topic and trigger the one-time fetching
  ndn_name_t name;
  ndn_name_init(&name);
  topic_t* entry = (topic_t*)userdata;
  _go_fetching(&name, entry);
}


void
ps_subscribe_to(uint8_t service, uint8_t type, const name_component_t* identifier, uint32_t component_size,
                uint32_t frequency, ndn_on_published callback)
{
  if (!m_has_initialized) 
    _ps_topics_init();

  int ret = 0;
  ndn_name_t name;
  ndn_name_init(&name);
  
  _name_construction(&name, type, service, identifier, component_size, 0);
  
  topic_t* entry = _match_topic(&name, SUB, MATCH_SHORT);
  if (entry) { 
    printf("ps_subscribe_to: already sub this one or a bigger topic, reject\n");
    return;
  }

  entry = _allocate_topic(callback, service, frequency, identifier, 
                                   component_size, SUB, type);
  if (!entry) { 
    printf("ps_subscribe_to: no topic entry available\n");
    return;
  }
  
  if (type == CMD) {
    //re-initialize the name for register use
    ndn_name_init(&name);
    _notification_prefix_register(&name, service, entry);
  }

  _periodic_data_fetching(NULL, 0, NULL);
  return;
}

void
ps_publish_content(uint8_t service, const name_component_t* identifier, uint32_t component_size,
                   uint8_t* content, uint32_t content_len) {
  _ps_publish(service, DATA, identifier, component_size, content, content_len);
}

void
ps_publish_command(uint8_t service, uint16_t action, const name_component_t* identifier, 
                   uint32_t component_size) {
  
  // I have no clear idea what we put in the command Data packet. 
  // Solution here is just memcpy the action bytes into content
  uint8_t act[2] = {0};
  memcpy(act, &action, sizeof(action));

  // express the /Notify Interest
  _notify(service, identifier, component_size);

  // prepare the Data packet
  _ps_publish(service, CMD, identifier, component_size, act, sizeof(act));
}
