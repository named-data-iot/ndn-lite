#include "metainfo.h"

int
ndn_metainfo_tlv_decode(ndn_decoder_t* decoder, ndn_metainfo_t* meta)
{
  uint32_t probe = 0;
  decoder_get_type(decoder, &probe);

  if (probe != TLV_MetaInfo) {
    if (probe == TLV_Content || probe == TLV_SignatureInfo) {
      ndn_metainfo_init(meta);
      return 0;
    }
    else
      return NDN_ERROR_WRONG_TLV_TYPE;
  }
  ndn_metainfo_init(meta);
  uint32_t buffer_length = 0;
  decoder_get_length(decoder, &buffer_length);
  uint32_t value_starting = decoder->offset;

  while (decoder->offset < value_starting + buffer_length) {
    decoder_get_type(decoder, &probe);
    if (probe == TLV_ContentType) {
      decoder_get_length(decoder, &probe);
      decoder_get_byte_value(decoder, &meta->content_type);
      meta->enable_ContentType = 1;
    }
    else if (probe == TLV_FreshnessPeriod) {
      decoder_get_length(decoder, &probe);
      decoder_get_raw_buffer_value(decoder, meta->freshness_period, 4);
      meta->enable_FreshnessPeriod = 1;
    }
    else if (probe == TLV_FinalBlockId) {
      decoder_get_length(decoder, &probe);
      name_component_tlv_decode(decoder, &meta->final_block_id);
      meta->enable_FinalBlockId = 1;
    }
    else
      return NDN_ERROR_WRONG_TLV_TYPE;
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
  uint32_t meta_value_size = 0;
  uint32_t comp_tlv_size = 0;
  if (meta->enable_ContentType) {
    meta_value_size += encoder_probe_block_size(TLV_ContentType, 1);
  }
  if (meta->enable_FreshnessPeriod) {
    meta_value_size += encoder_probe_block_size(TLV_FreshnessPeriod, 4);
  }
  if (meta->enable_FinalBlockId) {
    comp_tlv_size = name_component_probe_block_size(&meta->final_block_id);
    meta_value_size += encoder_probe_block_size(TLV_FinalBlockId, comp_tlv_size);
  }

  if (meta_value_size == 0)
    return 0;

  if (encoder->offset + encoder_probe_block_size(TLV_MetaInfo, meta_value_size)
      > encoder->output_max_size)
    return NDN_ERROR_OVERSIZE;

  encoder_append_type(encoder, TLV_MetaInfo);
  encoder_append_length(encoder, meta_value_size);

  if (meta->enable_ContentType) {
    encoder_append_type(encoder, TLV_ContentType);
    encoder_append_length(encoder, 1);
    encoder_append_byte_value(encoder, meta->content_type);
  }
  if (meta->enable_FreshnessPeriod) {
    encoder_append_type(encoder, TLV_FreshnessPeriod);
    encoder_append_length(encoder, 4);
    encoder_append_raw_buffer_value(encoder, meta->freshness_period, 4);
  }
  if (meta->enable_FinalBlockId) {
    encoder_append_type(encoder, TLV_FinalBlockId);
    encoder_append_length(encoder, comp_tlv_size);
    name_component_tlv_encode(encoder, &meta->final_block_id);
  }
  return 0;
}
