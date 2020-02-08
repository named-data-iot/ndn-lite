/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "interest.h"
#include "../ndn-constants.h"
#include "../security/ndn-lite-sha.h"
#include "../util/uniform-time.h"

/************************************************************/
/*  Definition of helper functions                          */
/************************************************************/

// get the length of tlv's v of the interest
static uint32_t
ndn_interest_probe_block_value_size(const ndn_interest_t* interest)
{
  uint32_t interest_buffer_size = ndn_name_probe_block_size(&interest->name);
  // can be prefix
  if (ndn_interest_get_CanBePrefix(interest))
    interest_buffer_size += 2;
  // must be fresh
  if (ndn_interest_get_MustBeFresh(interest))
    interest_buffer_size += 2;
  // nonce
  interest_buffer_size += 6;
  // life time
  interest_buffer_size += 2 + encoder_probe_uint_length(interest->lifetime); // lifetime
  // hop limit
  if (ndn_interest_has_HopLimit(interest))
    interest_buffer_size += 3;
  // parameters
  if (ndn_interest_has_Parameters(interest))
    interest_buffer_size += encoder_probe_block_size(TLV_ApplicationParameters, interest->parameters.size);
  if (ndn_interest_is_signed(interest)) {
    // signature info
    interest_buffer_size += ndn_signature_info_probe_block_size(&interest->signature);
    // signature value
    interest_buffer_size += ndn_signature_value_probe_block_size(&interest->signature);
  }
  return interest_buffer_size;
}

/************************************************************/
/*  Definition of Interest APIs                             */
/************************************************************/

void
ndn_interest_from_name(ndn_interest_t* interest, const ndn_name_t* name)
{
  memcpy(&interest->name, name, sizeof(ndn_name_t));
  interest->flags = 0;
  interest->nonce = 0;
  interest->lifetime = NDN_DEFAULT_INTEREST_LIFETIME;
  interest->hop_limit = 0;
}

int
ndn_interest_from_block(ndn_interest_t* interest, const uint8_t* block_value, uint32_t block_size)
{
  int ret_val = -1;
  ndn_interest_init(interest);
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  uint32_t type = 0;
  ret_val = decoder_get_type(&decoder, &type);
  if (ret_val != NDN_SUCCESS) return ret_val;
  if (type != TLV_Interest) {
    return NDN_WRONG_TLV_TYPE;
  }
  uint32_t interest_buffer_length = 0;
  ret_val = decoder_get_length(&decoder, &interest_buffer_length);
  if (ret_val != NDN_SUCCESS) return ret_val;

  // name
  int result = ndn_name_tlv_decode(&decoder, &interest->name);
  if (result < 0) {
    return result;
  }
  while (decoder.offset < block_size) {
    ret_val = decoder_get_type(&decoder, &type);
    if (ret_val != NDN_SUCCESS) return ret_val;
    uint32_t length = 0;
    if (type == TLV_CanBePrefix) {
      BIT_SET(interest->flags, 0);
      ret_val = decoder_get_length(&decoder, &length);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (type == TLV_MustBeFresh) {
      BIT_SET(interest->flags, 1);
      ret_val = decoder_get_length(&decoder, &length);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (type == TLV_Nonce) {
      ret_val = decoder_get_length(&decoder, &length);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_uint32_value(&decoder, &interest->nonce);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (type == TLV_InterestLifetime) {
      ret_val = decoder_get_length(&decoder, &length);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_uint_value(&decoder, length, &interest->lifetime);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (type == TLV_HopLimit) {
      BIT_SET(interest->flags, 2);
      ret_val = decoder_get_length(&decoder, &length);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_byte_value(&decoder, &interest->hop_limit);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (type == TLV_ApplicationParameters) {
      BIT_SET(interest->flags, 6);
      ret_val = decoder_get_length(&decoder, &interest->parameters.size);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_raw_buffer_value(&decoder, interest->parameters.value,
				   interest->parameters.size);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (type == TLV_InterestSignatureInfo) {
      BIT_SET(interest->flags, 7);
      ret_val = decoder_move_backward(&decoder, encoder_get_var_size(TLV_InterestSignatureInfo));
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = ndn_signature_info_tlv_decode(&decoder, &interest->signature);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (type == TLV_InterestSignatureValue) {
      BIT_SET(interest->flags, 7);
      ret_val = decoder_move_backward(&decoder, encoder_get_var_size(TLV_InterestSignatureValue));
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = ndn_signature_value_tlv_decode(&decoder, &interest->signature);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else {
      // return NDN_WRONG_TLV_TYPE;
      // in order to ensure backwards compatibility with NDN packet format v2, if there is an
      // unrecognizable tlv block (i.e. selector tlv block with tlv type 0x09), just skip over the
      // entire tlv block
      ret_val = decoder_get_length(&decoder, &length);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_move_forward(&decoder, length);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
  }
  return 0;
}

int
ndn_interest_tlv_encode(ndn_encoder_t* encoder, ndn_interest_t* interest)
{
  int ret_val = -1;

  if (ndn_interest_has_Parameters(interest) && !ndn_interest_is_signed(interest)) {
    if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE) {
      return NDN_OVERSIZE;
    }
    uint8_t be_hashed[NDN_INTEREST_PARAMS_BLOCK_SIZE] = {0};
    ndn_encoder_t temp_encoder;
    encoder_init(&temp_encoder, be_hashed, NDN_INTEREST_PARAMS_BLOCK_SIZE);
    ret_val = encoder_append_type(&temp_encoder, TLV_ApplicationParameters);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(&temp_encoder, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = ndn_sha256(temp_encoder.output_value, temp_encoder.offset,
                         interest->name.components[interest->name.components_size].value);
    interest->name.components[interest->name.components_size].type = TLV_ParametersSha256DigestComponent;
    interest->name.components[interest->name.components_size].size = NDN_SEC_SHA256_HASH_SIZE;
    interest->name.components_size += 1;
  }

  uint32_t interest_block_value_size = ndn_interest_probe_block_value_size(interest);
  int required_size = encoder_probe_block_size(TLV_Interest, interest_block_value_size);
  int rest_size = encoder->output_max_size - encoder->offset;
  if (required_size > rest_size)
    return NDN_OVERSIZE;

  ret_val = encoder_append_type(encoder, TLV_Interest);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, interest_block_value_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // name
  ret_val = ndn_name_tlv_encode(encoder, &interest->name);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // can be prefix
  if (ndn_interest_get_CanBePrefix(interest)) {
    ret_val = encoder_append_type(encoder, TLV_CanBePrefix);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, 0);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  // must be fresh
  if (ndn_interest_get_MustBeFresh(interest)) {
    ret_val = encoder_append_type(encoder, TLV_MustBeFresh);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, 0);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  // nonce
  if (interest->nonce == 0) {
    interest->nonce = (uint32_t) ndn_time_now_ms();
  }
  ret_val = encoder_append_type(encoder, TLV_Nonce);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, 4);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_uint32_value(encoder, interest->nonce);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // lifetime
  ret_val = encoder_append_type(encoder, TLV_InterestLifetime);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, encoder_probe_uint_length(interest->lifetime));
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_uint_value(encoder, interest->lifetime);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // hop limit
  if (ndn_interest_has_HopLimit(interest)) {
    ret_val = encoder_append_type(encoder, TLV_HopLimit);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, 1);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_byte_value(encoder, interest->hop_limit);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  // parameters
  if (ndn_interest_has_Parameters(interest)) {
    ret_val = encoder_append_type(encoder, TLV_ApplicationParameters);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(encoder, interest->parameters.value, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  if (ndn_interest_is_signed(interest)) {
    // signature info
    ret_val = ndn_signature_info_tlv_encode(encoder, &interest->signature);
    if (ret_val != NDN_SUCCESS) return ret_val;
    // signature value
    ret_val = ndn_signature_value_tlv_encode(encoder, &interest->signature);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  return 0;
}

int
ndn_interest_name_compare_block(const uint8_t* lhs_block_value, uint32_t lhs_block_size,
                                const uint8_t* rhs_block_value, uint32_t rhs_block_size)
{
  int ret_val = -1;

  ndn_decoder_t lhs_decoder, rhs_decoder;
  uint32_t lhs_interest_buffer_length, rhs_interest_buffer_length = 0;
  decoder_init(&lhs_decoder, lhs_block_value, lhs_block_size);
  decoder_init(&rhs_decoder, rhs_block_value, rhs_block_size);
  uint32_t probe = 0;

  /* check left interest type */
  ret_val = decoder_get_type(&lhs_decoder, &probe);
  if (ret_val != NDN_SUCCESS)
    return ret_val;
  if (probe != TLV_Interest)
    return NDN_WRONG_TLV_TYPE;

  /* check right interest type */
  ret_val = decoder_get_type(&rhs_decoder, &probe);
  if (ret_val != NDN_SUCCESS)
    return ret_val;
  if (probe != TLV_Interest)
    return NDN_WRONG_TLV_TYPE;

  /* check left interest buffer length */
  ret_val = decoder_get_length(&lhs_decoder, &lhs_interest_buffer_length);
  if (ret_val != NDN_SUCCESS) return ret_val;

  /* check right interest buffer length */
  ret_val = decoder_get_length(&rhs_decoder, &rhs_interest_buffer_length);
  if (ret_val != NDN_SUCCESS) return ret_val;

  /* compare Names */
  ret_val = ndn_name_compare_block(lhs_decoder.input_value + lhs_decoder.offset,
                                   lhs_decoder.input_size - lhs_decoder.offset,
                                   rhs_decoder.input_value + rhs_decoder.offset,
                                   rhs_decoder.input_size - rhs_decoder.offset);
  return ret_val;
}
