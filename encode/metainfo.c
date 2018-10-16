#include "metainfo.h"
#include <stdio.h>

int
ndn_metainfo_tlv_decode(ndn_metainfo_t* meta, ndn_block_t* block)
{
    ndn_decoder_t decoder;
    uint32_t probe;
    decoder_init(&decoder, block->value, block->size);
    decoder_get_type(&decoder, &probe);
    decoder_get_length(&decoder, &probe);
    size_t total_length = probe;

    uint8_t array[total_length];
    const uint8_t* buf = array;

    ndn_buffer_t buffer = { array, total_length };
    decoder_get_buffer_value(&decoder, &buffer);

    uint8_t contenttype_array[METAINFO_CONTENTTYPE_BLOCK_SIZE];
    ndn_block_t contenttype = { contenttype_array, METAINFO_CONTENTTYPE_BLOCK_SIZE };
    memcpy(contenttype_array, buf, METAINFO_CONTENTTYPE_BLOCK_SIZE);
    buf += METAINFO_CONTENTTYPE_BLOCK_SIZE;
    contenttype_decode(&meta->content_type, &contenttype);

    uint8_t freshness_array[METAINFO_FRESHNESS_BLOCK_SIZE];
    ndn_block_t fresh = { freshness_array, METAINFO_FRESHNESS_BLOCK_SIZE };
    memcpy(freshness_array, buf, METAINFO_FRESHNESS_BLOCK_SIZE);
    buf += METAINFO_FRESHNESS_BLOCK_SIZE;
    freshness_decode(&meta->freshness, &fresh);

    uint8_t finalblockid_array[METAINFO_FINALBLOCKID_BLOCK_SIZE];
    ndn_block_t finalblockid = { freshness_array, METAINFO_FINALBLOCKID_BLOCK_SIZE };
    memcpy(finalblockid_array, buf, METAINFO_FINALBLOCKID_BLOCK_SIZE);
    finalblockid_decode(&meta->finalblock_id, &finalblockid);

    return 0;
}

int
ndn_metainfo_tlv_encode(ndn_metainfo_t* meta, ndn_block_t* output)
{
  ndn_encoder_t encoder;
  int result;

  encoder_init(&encoder, output->value, output->size);
  encoder_append_type(&encoder, TLV_MetaInfo);

  size_t comp_size = name_component_probe_block_size(&meta->finalblock_id);
  size_t blockid_size = comp_size = 2;
  size_t value_size = METAINFO_CONTENTTYPE_BLOCK_SIZE + METAINFO_FRESHNESS_BLOCK_SIZE
                      + blockid_size + 2;
  encoder_append_length(&encoder, value_size);

  uint8_t value_contenttype[METAINFO_CONTENTTYPE_BLOCK_SIZE];
  ndn_block_t content_type = { value_contenttype, METAINFO_CONTENTTYPE_BLOCK_SIZE };
  contenttype_encode(&meta->content_type, &content_type);
  result = encoder_append_raw_buffer_value(&encoder, content_type.value, content_type.size);
  if (result < 0) return result;

  uint8_t value_freshness[METAINFO_FRESHNESS_BLOCK_SIZE];
  ndn_block_t freshness = { value_freshness, METAINFO_FRESHNESS_BLOCK_SIZE };
  freshness_encode(&meta->freshness, &freshness);
  result = encoder_append_raw_buffer_value(&encoder, freshness.value, freshness.size);
  if (result < 0) return result;
  
  uint8_t value_finalblockid[METAINFO_FINALBLOCKID_BLOCK_SIZE];
  ndn_block_t finalblock_id = { value_finalblockid, METAINFO_FRESHNESS_BLOCK_SIZE };
  finalblockid_encode(&meta->finalblock_id, &finalblock_id);
  result = encoder_append_raw_buffer_value(&encoder, finalblock_id.value, finalblock_id.size);
  if (result < 0) return result;
 
  return 0;
}
