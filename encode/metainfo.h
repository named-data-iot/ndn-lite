#ifndef NDN_ENCODING_METAINFO_H
#define NDN_ENCODING_METAINFO_H

#include "name.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_metainfo {
  uint8_t content_type;
  uint8_t freshness_period[4];
  name_component_t final_block_id;

  uint8_t enable_ContentType;
  uint8_t enable_FreshnessPeriod;
  uint8_t enable_FinalBlockId;
} ndn_metainfo_t;

static inline void
ndn_metainfo_init(ndn_metainfo_t *meta)
{
  meta->enable_ContentType = 0;
  meta->enable_FreshnessPeriod = 0;
  meta->enable_FinalBlockId = 0;
}

// will do memory copy
static inline void
ndn_metainfo_from_other(ndn_metainfo_t* meta, const ndn_metainfo_t* other)
{
  memcpy(meta, other, sizeof(ndn_metainfo_t));
}

int
ndn_metainfo_tlv_decode(ndn_decoder_t* decoder, ndn_metainfo_t* meta);

// add a _tlv_ to avoid conflicts with the existing encoding
int
ndn_metainfo_from_tlv_block(ndn_metainfo_t* meta, const uint8_t* block_value, uint32_t block_size);

static inline void
ndn_metainfo_set_content_type(ndn_metainfo_t* meta, uint8_t content_type)
{
  meta->enable_ContentType = 1;
  meta->content_type = content_type;
}

static inline void
ndn_metainfo_set_freshness_period(ndn_metainfo_t *meta, uint32_t freshness_period)
{
  meta->enable_FreshnessPeriod = 1;
  meta->freshness_period[0] = (freshness_period >> 24) & 0xFF;
  meta->freshness_period[1] = (freshness_period >> 16) & 0xFF;
  meta->freshness_period[2] = (freshness_period >> 8) & 0xFF;
  meta->freshness_period[3] = freshness_period & 0xFF;
}

static inline void
ndn_metainfo_set_final_block_id(ndn_metainfo_t *meta, const name_component_t* final_block_id)
{
  meta->enable_FinalBlockId = 1;
  memcpy(&meta->final_block_id, final_block_id, sizeof(name_component_t));
}

static inline uint32_t
ndn_metainfo_probe_block_size(const ndn_metainfo_t* meta)
{
  uint32_t meta_value_size = 0;
  if (meta->enable_ContentType) {
    meta_value_size += encoder_probe_block_size(TLV_ContentType, 1);
  }
  if (meta->enable_FreshnessPeriod) {
    meta_value_size += encoder_probe_block_size(TLV_FreshnessPeriod, 4);
  }
  if (meta->enable_FinalBlockId) {
    uint32_t comp_tlv_size = name_component_probe_block_size(&meta->final_block_id);
    meta_value_size += encoder_probe_block_size(TLV_FinalBlockId, comp_tlv_size);
  }

  if (meta_value_size == 0) {
    return 0;
  }
  else {
    return encoder_probe_block_size(TLV_MetaInfo, meta_value_size);
  }
}

int
ndn_metainfo_tlv_encode(ndn_encoder_t* encoder, const ndn_metainfo_t *meta);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_NAME_H
