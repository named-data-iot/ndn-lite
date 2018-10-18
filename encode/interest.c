/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "interest.h"

int
ndn_interest_from_block(ndn_interest_t* interest, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  uint32_t type = 0;
  decoder_get_type(&decoder, &type);
  if (type != TLV_Interest) {
    return NDN_ERROR_WRONG_TLV_TYPE;
  }
  uint32_t interest_buffer_length = 0;
  decoder_get_length(&decoder, &interest_buffer_length);

  // name
  int result = ndn_name_decode(&decoder, &interest->name);
  if (result < 0) {
    return result;
  }
  while (decoder.offset < block_size) {
    decoder_get_type(&decoder, &type);
    uint32_t length = 0;
    if (type == TLV_CanBePrefix) {
      interest->enable_CanBePrefix = 1;
      decoder_get_length(&decoder, &length);
    }
    else if (type == TLV_MustBeFresh) {
      interest->enable_MustBeFresh = 1;
      decoder_get_length(&decoder, &length);
    }
    else if (type == TLV_Nounce) {
      decoder_get_length(&decoder, &length);
      decoder_get_raw_buffer_value(&decoder, interest->nounce, length);
    }
    else if (type == TLV_InterestLifetime) {
      decoder_get_length(&decoder, &length);
      decoder_get_raw_buffer_value(&decoder, interest->lifetime, length);
    }
    else if (type == TLV_HopLimit) {
      interest->enable_HopLimit = 1;
      decoder_get_length(&decoder, &length);
      decoder_get_byte_value(&decoder, &interest->hop_limit);
    }
    else if (type == TLV_Parameters) {
      interest->enable_Parameters = 1;
      decoder_get_length(&decoder, &interest->parameters.size);
      decoder_get_raw_buffer_value(&decoder, interest->parameters.value,
                                   interest->parameters.size);
    }
    else
      return NDN_ERROR_WRONG_TLV_TYPE;
  }
  return 0;
}

int
ndn_interest_encode(const ndn_interest_t* interest, uint8_t* block_value, uint8_t block_max_size,
                    uint32_t* used_block_size)
{
  ndn_encoder_t encoder;
  encoder_init(&encoder, block_value, block_max_size);
  encoder_append_type(&encoder, TLV_Interest);

  uint32_t interest_block_size = ndn_interest_probe_block_size(interest);

  encoder_append_length(&encoder, interest_block_size);
  ndn_name_tlv_encode(&encoder, &interest->name);

  if (interest->enable_CanBePrefix) {
    encoder_append_type(&encoder, TLV_CanBePrefix);
    encoder_append_length(&encoder, 0);
  }
  if (interest->enable_MustBeFresh) {
    encoder_append_type(&encoder, TLV_MustBeFresh);
    encoder_append_length(&encoder, 0);
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
    encoder_append_length(&encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(&encoder, interest->parameters.value, interest->parameters.size);
  }
  *used_block_size = encoder.offset;
  return 0;
}
