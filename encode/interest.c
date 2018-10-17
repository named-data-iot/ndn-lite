/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "interest.h"

// int
// ndn_interest_from_block(ndn_interest_t* interest, uint8_t* block_value, uint32_t block_size)
// {
//   interest->nounce = 0;
//   return 0;
// }

int
ndn_interest_encode(ndn_interest_t* interest, uint8_t* block_value, uint8_t block_max_size)
{
  ndn_encoder_t encoder;
  encoder_init(&encoder, block_value, block_max_size);
  encoder_append_type(&encoder, TLV_Interest);

  uint32_t interest_block_size = ndn_interest_probe_block_size(interest);

  encoder_append_length(&encoder, interest_block_size);
  ndn_name_tlv_encode(&encoder, interest->name);

  if (interest->enable_CanBePrefix) {
    encoder_append_type(&encoder, TLV_CanBePrefix);
    encoder_append_length(&encoder, 0);
  }
  if (interest->enable_MustBeFresh) {
    encoder_append_type(&encoder, TLV_MustBeFresh);
    encoder_append_length(&encoder, 0);
    encoder_append_var(&encoder, 0);
  }
  // nounce
  encoder_append_type(&encoder, TLV_Nounce);
  encoder_append_length(&encoder, 4);
  encoder_append_raw_buffer_value(&encoder, interest->nounce, 4);
  // lifetime
  encoder_append_type(&encoder, TLV_InterestLifetime);
  encoder_append_length(&encoder, 2);
  encoder_append_raw_buffer_value(&encoder, interest->lifetime, 2);
  if (interest->enable_HopLimit) {
    encoder_append_type(&encoder, TLV_HopLimit);
    encoder_append_length(&encoder, 1);
    encoder_append_byte_value(&encoder, interest->hop_limit);
  }
  if (interest->enable_Parameters) {
    encoder_append_type(&encoder, TLV_Parameters);
    encoder_append_length(&encoder, interest->parameters->size);
    encoder_append_raw_buffer_value(&encoder, interest->parameters->value, interest->parameters->size);
  }
  return 0;
}
