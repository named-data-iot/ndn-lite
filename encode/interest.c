/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "interest.h"

/************************************************************/
/*  Definition of helper functions                          */
/************************************************************/

// get the length of inner tlv's of the interest
// used only for unsigned interest
static uint32_t
ndn_interest_probe_block_internals_size(const ndn_interest_t* interest)
{
  uint32_t interest_buffer_internals_size = ndn_name_probe_block_size(&interest->name);
  if (interest->enable_CanBePrefix)
    interest_buffer_internals_size += 2;
  if (interest->enable_MustBeFresh)
    interest_buffer_internals_size += 2;
  if (interest->enable_HopLimit)
    interest_buffer_internals_size += 3;
  if (interest->enable_Parameters)
    interest_buffer_internals_size += encoder_probe_block_size(TLV_Parameters, interest->parameters.size);
  interest_buffer_internals_size += 6; // nonce
  interest_buffer_internals_size += 4; // lifetime
  return interest_buffer_internals_size;
}

/************************************************************/
/*  Definition of Interest APIs                             */
/************************************************************/

int
ndn_interest_from_block(ndn_interest_t* interest, const uint8_t* block_value, uint32_t block_size)
{
  ndn_interest_init(interest);

  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  uint32_t type = 0;
  decoder_get_type(&decoder, &type);
  if (type != TLV_Interest) {
    return NDN_WRONG_TLV_TYPE;
  }
  uint32_t interest_buffer_length = 0;
  decoder_get_length(&decoder, &interest_buffer_length);

  // name
  int result = ndn_name_tlv_decode(&decoder, &interest->name);
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
    else if (type == TLV_Nonce) {
      decoder_get_length(&decoder, &length);
      decoder_get_uint32_value(&decoder, &interest->nonce);
    }
    else if (type == TLV_InterestLifetime) {
      decoder_get_length(&decoder, &length);
      decoder_get_uint16_value(&decoder, &interest->lifetime);
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
    else if (type == TLV_SignedInterestParameters) {
      uint32_t probe = 0;
      interest->is_SignedInterest = 1;
      decoder_get_length(&decoder, &probe);
      decoder_get_type(&decoder, &probe);
      if (probe == TLV_Parameters) {
        interest->enable_Parameters = 1;
        decoder_get_length(&decoder, &probe);
        if (probe > NDN_INTEREST_PARAMS_BUFFER_SIZE) {
          return NDN_OVERSIZE;
        }
        interest->parameters.size = probe;
        decoder_get_raw_buffer_value(&decoder, interest->parameters.value,
                                     interest->parameters.size);
        decoder_get_type(&decoder, &probe);
      }
      // timestamp
      decoder_get_length(&decoder, &probe);
      decoder_get_uint32_value(&decoder, &interest->signature_timestamp);
      // nonce
      decoder_get_type(&decoder, &probe);
      decoder_get_length(&decoder, &probe);
      decoder_get_uint32_value(&decoder, &interest->signature_nonce);
      // signature info
      ndn_signature_info_tlv_decode(&decoder, &interest->signature);
    }
    else if (type == TLV_SignatureValue) {
      decoder_move_backward(&decoder, encoder_get_var_size(TLV_SignatureValue));
      ndn_signature_value_tlv_decode(&decoder, &interest->signature);
    }
    else
      return NDN_WRONG_TLV_TYPE;
  }
  return 0;
}

int
ndn_interest_tlv_encode(ndn_encoder_t* encoder, const ndn_interest_t* interest)
{
  uint32_t interest_block_value_size = ndn_interest_probe_block_internals_size(interest);
  int required_size = encoder_probe_block_size(TLV_Interest, interest_block_value_size);
  int rest_size = encoder->output_max_size - encoder->offset;
  if (required_size > rest_size)
    return NDN_OVERSIZE;

  encoder_append_type(encoder, TLV_Interest);
  encoder_append_length(encoder, interest_block_value_size);
  ndn_name_tlv_encode(encoder, &interest->name);

  if (interest->enable_CanBePrefix) {
    encoder_append_type(encoder, TLV_CanBePrefix);
    encoder_append_length(encoder, 0);
  }
  if (interest->enable_MustBeFresh) {
    encoder_append_type(encoder, TLV_MustBeFresh);
    encoder_append_length(encoder, 0);
  }

  // nonce
  encoder_append_type(encoder, TLV_Nonce);
  encoder_append_length(encoder, 4);
  encoder_append_uint32_value(encoder, interest->nonce);

  // lifetime
  encoder_append_type(encoder, TLV_InterestLifetime);
  encoder_append_length(encoder, 2);
  encoder_append_uint16_value(encoder, interest->lifetime);
  if (interest->enable_HopLimit) {
    encoder_append_type(encoder, TLV_HopLimit);
    encoder_append_length(encoder, 1);
    encoder_append_byte_value(encoder, interest->hop_limit);
  }
  if (interest->enable_Parameters) {
    encoder_append_type(encoder, TLV_Parameters);
    encoder_append_length(encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(encoder, interest->parameters.value, interest->parameters.size);
  }
  return 0;
}
