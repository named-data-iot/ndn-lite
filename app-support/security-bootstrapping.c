/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#include "security-bootstrapping.h"
#include "../encode/interest.h"
#include "../encode/data.h"
#include "../encode/key-storage.h"
#include "../util/uniform-time.h"

typedef struct ndn_sec_boot_state {
  int placeholder;
} ndn_sec_boot_state_t;

static ndn_sec_boot_state_t m_sec_boot_state;

// some common rules: 1. keep keys in key_storage 2. delete the key from key storage if its not used any longer

void
sec_boot_send_cert_interest() {
  // generate the cert interest (2nd interest)
  // send it out
}

void
on_sign_on_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse received data
  ndn_data_t data;
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
  printf("Receive SD related Data packet with name: \n");
  ndn_name_print(&data.name);
  ndn_time_ms_t now = ndn_time_now_ms();
  ndn_name_t service_full_name;
  uint32_t freshness_period = 0;
  // parse content
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  // TODO
  // send cert interest
  sec_boot_send_cert_interest();
}

void
sec_boot_send_sign_on_interest() {
  // generate the sign on interest  (1st interest)
  // send it out
}

void
on_cert_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse received data
  ndn_data_t data;
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
  printf("Receive SD related Data packet with name: \n");
  ndn_name_print(&data.name);
  ndn_time_ms_t now = ndn_time_now_ms();
  ndn_name_t service_full_name;
  uint32_t freshness_period = 0;
  // parse content
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  // TODO
  // finish the bootstrapping process
}

void
ndn_security_bootstrapping()
{
  // send the first interest out
  sec_boot_send_sign_on_interest();
}