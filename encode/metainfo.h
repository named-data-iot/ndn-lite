#ifndef ENCODING_METAINFO_H
#define ENCODING_METAINFO_H

#include "tlv.h"
#include "encoder.h"
#include "decoder.h"
#include "name.h"
#include "ndn_constants.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Type to represent NDN metainfo.
 */
typedef struct ndn_metainfo {
    int32_t content_type;    /**< content type; -1 if not present */
    int32_t freshness;       /**< freshness period; -1 if not present */
    name_component_t finalblock_id;
} ndn_metainfo_t;

// will do memory copy
static inline int
ndn_metainfo_init(ndn_metainfo_t *meta, int32_t content_type, int32_t freshness, const name_component_t* finalblock_id){
    meta->content_type = content_type;
    meta->freshness = freshness;
    meta->finalblock_id.size = finalblock_id->size;
    meta->finalblock_id.type = finalblock_id->type;
    memcpy(meta->finalblock_id.value, finalblock_id->value, finalblock_id->size);
    return 0;
}

// will do memory copy
static inline int
ndn_metainfo_from_other(ndn_metainfo_t* meta, const ndn_metainfo_t* other){
    meta->content_type = other->content_type;
    meta->freshness = other->freshness;
    meta->finalblock_id.size = other->finalblock_id.size;
    meta->finalblock_id.type = other->finalblock_id.type;
    memcpy(meta->finalblock_id.value, other->finalblock_id.value, other->finalblock_id.size);
    return 0;
}

static inline int
contenttype_encode(int32_t* content_type, ndn_block_t* output){
    ndn_encoder_t encoder;
    encoder_init(&encoder, output->value, METAINFO_CONTENTTYPE_BLOCK_SIZE);
    encoder_append_type(&encoder, TLV_ContentType);
    encoder_append_length(&encoder, 4);
    encoder_append_raw_buffer_value(&encoder, (uint8_t*)content_type, 4);
    output->size = encoder.offset;
    return 0;
}

static inline int
contenttype_decode(int32_t* content_type, ndn_block_t* block){
  ndn_decoder_t decoder;
  uint32_t probe;
  ndn_buffer_t contenttype;
  
  decoder_init(&decoder, block->value, block->size);
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  decoder_get_raw_buffer_value(&decoder, contenttype.value, contenttype.size);
 
  if(contenttype.size < 4) return contenttype.size;
  memcpy(content_type, contenttype.value, contenttype.size);
  return 0;
}

static inline int
freshness_encode(int32_t* freshness, ndn_block_t* output){
    ndn_encoder_t encoder;
    encoder_init(&encoder, output->value, METAINFO_FRESHNESS_BLOCK_SIZE);
    encoder_append_type(&encoder, TLV_FreshnessPeriod);
    encoder_append_length(&encoder, 4);
    encoder_append_raw_buffer_value(&encoder, (uint8_t*)freshness, 4);
    output->size = encoder.offset;
    return 0;
}

static inline int
freshness_decode(int32_t* freshness, ndn_block_t* block){
  ndn_decoder_t decoder;
  uint32_t probe;
  ndn_buffer_t fresh;
  
  decoder_init(&decoder, block->value, block->size);
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  decoder_get_raw_buffer_value(&decoder, fresh.value, fresh.size);
 
  if(fresh.size < 4) return fresh.size;
  memcpy(freshness, fresh.value, fresh.size);
  return 0;
}

static inline int
finalblockid_encode(name_component_t* finalblock_id, ndn_block_t* output){
    ndn_encoder_t encoder;
    encoder_init(&encoder, output->value, METAINFO_FINALBLOCKID_BLOCK_SIZE);
    encoder_append_type(&encoder, TLV_FinalBlockId);

    size_t comp_size = name_component_probe_block_size(finalblock_id);
    name_component_block_t comp_block;
    name_component_tlv_encode(finalblock_id, &comp_block);
    encoder_append_length(&encoder, comp_size);

    encoder_append_raw_buffer_value(&encoder, comp_block.value, comp_block.size);
    output->size = encoder.offset;
    return 0;
}

static inline int
finalblockid_decode(name_component_t* finalblock_id, ndn_block_t* block){
  ndn_decoder_t decoder;
  uint32_t probe;
  ndn_block_t finalblockid;
  
  decoder_init(&decoder, block->value, block->size);
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  decoder_get_raw_buffer_value(&decoder, finalblockid.value, finalblockid.size);
 
  decoder_init(&decoder, finalblockid.value, finalblockid.size);
  decoder_get_type(&decoder, &finalblock_id->type);
  decoder_get_length(&decoder, &finalblock_id->size);
  decoder_get_raw_buffer_value(&decoder, finalblock_id->value, finalblock_id->size);  
  return 0;
}

int
ndn_metainfo_tlv_encode(ndn_metainfo_t *meta, ndn_block_t* output);

#ifdef __cplusplus
}
#endif

#endif // ENCODING_NAME_H
