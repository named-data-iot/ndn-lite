/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "metainfo.h"

int
ndn_metainfo_tlv_decode(ndn_decoder_t* decoder, ndn_metainfo_t* meta)
{

  int ret_val = -1;
  
  uint32_t probe = 0;
  ret_val = decoder_get_type(decoder, &probe);
  if (ret_val != NDN_SUCCESS) return ret_val;
  
  if (probe != TLV_MetaInfo) {
    if (probe == TLV_Content || probe == TLV_SignatureInfo) {
      ndn_metainfo_init(meta);
      ret_val = decoder_move_backward(decoder, 1);
      if (ret_val != NDN_SUCCESS) return ret_val;
      return 0;
    }
    else {
      ret_val = decoder_move_backward(decoder, 1);
      if (ret_val != NDN_SUCCESS) return ret_val;
      return NDN_WRONG_TLV_TYPE;
    }
  }

  ndn_metainfo_init(meta);
  uint32_t buffer_length = 0;
  ret_val = decoder_get_length(decoder, &buffer_length);
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint32_t value_starting = decoder->offset;

  while (decoder->offset < value_starting + buffer_length) {
    ret_val = decoder_get_type(decoder, &probe);
    if (ret_val != NDN_SUCCESS) return ret_val;
    if (probe == TLV_ContentType) {
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_byte_value(decoder, &meta->content_type);
      if (ret_val != NDN_SUCCESS) return ret_val;
      meta->enable_ContentType = 1;
    }
    else if (probe == TLV_FreshnessPeriod) {
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_uint_value(decoder, probe, &meta->freshness_period);
      if (ret_val != NDN_SUCCESS) return ret_val;
      meta->enable_FreshnessPeriod = 1;
    }
    else if (probe == TLV_FinalBlockId) {
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = name_component_tlv_decode(decoder, &meta->final_block_id);
      if (ret_val != NDN_SUCCESS) return ret_val;
      meta->enable_FinalBlockId = 1;
    }
    else
      return NDN_WRONG_TLV_TYPE;
  }
  return 0;
}

int
ndn_metainfo_from_tlv_block(ndn_metainfo_t* meta, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  return ndn_metainfo_tlv_decode(&decoder, meta);
}

int
ndn_metainfo_tlv_encode(ndn_encoder_t* encoder, const ndn_metainfo_t* meta)
{

  int ret_val = -1;
  
  uint32_t meta_value_size = 0;
  uint32_t comp_tlv_size = 0;
  if (meta->enable_ContentType) {
    meta_value_size += encoder_probe_block_size(TLV_ContentType, 1);
  }
  if (meta->enable_FreshnessPeriod) {
    meta_value_size += encoder_probe_block_size(TLV_FreshnessPeriod, 
                                                encoder_probe_uint_length(meta->freshness_period));
  }
  if (meta->enable_FinalBlockId) {
    comp_tlv_size = name_component_probe_block_size(&meta->final_block_id);
    meta_value_size += encoder_probe_block_size(TLV_FinalBlockId, comp_tlv_size);
  }

  if (meta_value_size == 0)
    return 0;

  if (encoder->offset + encoder_probe_block_size(TLV_MetaInfo, meta_value_size)
      > encoder->output_max_size)
    return NDN_OVERSIZE;

  ret_val = encoder_append_type(encoder, TLV_MetaInfo);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, meta_value_size);
  if (ret_val != NDN_SUCCESS) return ret_val;

  if (meta->enable_ContentType) {
    ret_val = encoder_append_type(encoder, TLV_ContentType);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, 1);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_byte_value(encoder, meta->content_type);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  if (meta->enable_FreshnessPeriod) {
    ret_val = encoder_append_type(encoder, TLV_FreshnessPeriod);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, encoder_probe_uint_length(meta->freshness_period));
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_uint_value(encoder, meta->freshness_period);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  if (meta->enable_FinalBlockId) {
    ret_val = encoder_append_type(encoder, TLV_FinalBlockId);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, comp_tlv_size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = name_component_tlv_encode(encoder, &meta->final_block_id);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  return 0;
}
