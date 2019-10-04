/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "pub-sub.h"
#include "../encode/name.h"

// the struct to keep each topic subscribed
typedef struct topic {
  uint8_t service;
  name_component_t identifier[2];
  uint32_t interval; // the time interval between two Interests
  uint32_t next_interest; // the time to send next Interest
  ndn_on_content_published callback;
} topic_t;

// the struct to keep registered topics, including: service, identifer (name_components), frequency, and callback
typedef struct sub_topics {
  topic_t topics[10];
  uint32_t min_interval;
} sub_topics_t;

void
_match_topic(const ndn_name_t* data_name, topic_t* topic)
{
  // match the topics and load the matched topic into the topic
}

void
_on_new_content(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse Data name
  // match the subscription topic
  // call the on_content callback
}

void
_periodic_data_fetching(void *self, size_t param_length, void *param)
{
  // perodically send Interest packet
  // register the event to the message queue again with the smallest time period
}

void
_on_notification_interest()
{
  // parse notification interest
  // match the topic
  // send the Interest to fetch new content
}

void
_on_subscription_interest()
{
  // parse interest
  // match topic
  // reply the latest content
}

void
ps_subscribe_to(uint8_t service, char* identifier, uint32_t identifier_len,
                uint32_t frequency, ndn_on_content_published callback);

void
ps_publish_content(uint8_t service, uint16_t datatype, uint32_t datatype_len,
                   uint8_t* content, uint32_t content_len);

void
ps_publish_command(uint8_t service, uint16_t action, char* identifier, uint32_t identifier_len,
                   uint8_t* content, uint32_t content_len);
