/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCODING_METAINFO_H
#define NDN_ENCODING_METAINFO_H

#include "name.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to represent the Metainfo structure.
 */
typedef struct ndn_metainfo {
  /**
   * The freshness period of the Data packet.
   */
  uint64_t freshness_period;
  /**
   * The last name component in Name.
   */
  name_component_t final_block_id;
  /**
   * The content type the Data packet holds.
   */
  uint8_t content_type;
  
  uint8_t enable_ContentType;
  uint8_t enable_FreshnessPeriod;
  uint8_t enable_FinalBlockId;
} ndn_metainfo_t;

/**
 * Init a Metainfo structure.
 * @param meta. Output. The Metainfo structure to be inited.
 */
static inline void
ndn_metainfo_init(ndn_metainfo_t* meta)
{
  meta->enable_ContentType = 0;
  meta->enable_FreshnessPeriod = 0;
  meta->enable_FinalBlockId = 0;
}

/**
 * Init a Metainfo structure. This function will do memory copy.
 * @param meta. Output. The Metainfo structure to be inited.
 * @param other. Output. The Metainfo structure to be copied from.
 */
static inline void
ndn_metainfo_from_other(ndn_metainfo_t* meta, const ndn_metainfo_t* other)
{
  memcpy(meta, other, sizeof(ndn_metainfo_t));
}

/**
 * Decode the Metainfo from wire format (TLV block).
 * @param decoder. Input. The decoder who keeps the decoding result and the state.
 * @param meta. Output. The Metainfo decoded from TLV block.
 * @return 0 if there is no error.
 */
int
ndn_metainfo_tlv_decode(ndn_decoder_t* decoder, ndn_metainfo_t* meta);

/**
 * Decode a Metainfo TLV block into a ndn_metainfo_t.
 * @param meta. Output. The Metainfo to which the TLV block will be decoded.
 * @param block_value. Input. The Metainfo TLV block buffer.
 * @param block_size. Input. The size of the Metainfo TLV block buffer.
 * @return 0 if decoding is successful.
 */
int
ndn_metainfo_from_tlv_block(ndn_metainfo_t* meta, const uint8_t* block_value, uint32_t block_size);

/**
 * Set ContentType of the Metainfo.
 * @param meta. Output. The Metainfo whose ContentType will be set.
 * @param content_type. Input. ContentType value following NDN Packet Format Specification 0.3.
 */
static inline void
ndn_metainfo_set_content_type(ndn_metainfo_t* meta, uint8_t content_type)
{
  meta->enable_ContentType = 1;
  meta->content_type = content_type;
}

/**
 * Set FreshnessPeriod of the Metainfo.
 * @param meta. Output. The Metainfo whose FreshnessPeriod will be set.
 * @param freshness_period. Input. FreshnessPeriod value.
 */
static inline void
ndn_metainfo_set_freshness_period(ndn_metainfo_t* meta, uint64_t freshness_period)
{
  meta->enable_FreshnessPeriod = 1;
  meta->freshness_period = freshness_period;
}

/**
 * Set FinalBlockId of the Metainfo.
 * @param meta. Output. The Metainfo whose FinalBlockId will be set.
 * @param final_block_id. Input. The last component of Name.
 */
static inline void
ndn_metainfo_set_final_block_id(ndn_metainfo_t *meta, const name_component_t* final_block_id)
{
  meta->enable_FinalBlockId = 1;
  memcpy(&meta->final_block_id, final_block_id, sizeof(name_component_t));
}

/**
 * Probe the size of a Metainfo TLV block before encoding it from a Metainfo structure.
 * This function is used to check whether the output buffer size is enough or not.
 * @param meta. Input. The Metainfo structure to probe.
 * @return the length of the Metainfo TLV block.
 */
static inline uint32_t
ndn_metainfo_probe_block_size(const ndn_metainfo_t* meta)
{
  uint32_t meta_value_size = 0;
  if (meta->enable_ContentType) {
    meta_value_size += encoder_probe_block_size(TLV_ContentType, 1);
  }
  if (meta->enable_FreshnessPeriod) {
    meta_value_size += encoder_probe_block_size(TLV_FreshnessPeriod,
                                                encoder_probe_uint_length(meta->freshness_period));
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

/**
 * Encode the Metainfo structure into wire format (TLV block).
 * @param encoder. Output. The encoder who keeps the encoding result and the state.
 * @param meta. Input. The Metainfo structure to be encoded.
 * @return 0 if there is no error.
 */
int
ndn_metainfo_tlv_encode(ndn_encoder_t* encoder, const ndn_metainfo_t* meta);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_METAINFO_H
