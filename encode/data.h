/*
 * Copyright (C) Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NDN_ENCODING_DATA_H
#define NDN_ENCODING_DATA_H

#include "name.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ndn_data {
  ndn_name_t name;
  ndn_metainfo_t metainfo;
  uint_8 content_value[NDN_CONTENT_BUFFER_SIZE];
  uint32_t content_size;
  ndn_signature_t signature;
} ndn_data_t;

static inline int
ndn_data_init(ndn_data_t* data, uint8_t* content_value, uint32_t content_size)
{
  if (content_size < NDN_CONTENT_BUFFER_SIZE) {
    memcpy(data->content_value, content_value, content_size);
  }
  return 0;
}

// int
// ndn_data_hmac_sign(ndn_data_t* data, const uint8_t* prv_key_value, uint32_t prv_key_size);

// int
// ndn_data_verify(ndn_data_t* data);

static inline uint32_t
ndn_data_probe_unsigned_block_size(const ndn_data_t* data)
{
  uint32_t data_unsigned_block_size = ndn_name_probe_block_size(data->name);
  data_buffer_size += ndn_metainfo_probe_block_size(data->metainfo);
  data_buffer_size += encoder_probe_block_size(TLV_Content, data->content_size);
  data_buffer_size += ndn_signature_info_probe_block_size(data->signature);
  return data_unsigned_block_size;
}

int
ndn_data_prepare_unsigned_block(ndn_encoder_t* encoder, const ndn_data_t* data);

// int
// ndn_data_tlv_encode_digest_sign(const ndn_data_t* data);

// int
// ndn_data_tlv_encode_ecdsa_sign(const ndn_data_t* data, const ndn_name_t* producer_identity,
//                                const ndn_ecc_prv_t* prv_key);

// int
// ndn_data_tlv_encode_hmac_sign(const ndn_data_t* data, const ndn_name_t* producer_identity,
//                                const ndn_hmac_key_t* hmac_key);

// int
// ndn_data_tlv_decode(const ndn_data_t* data, const uint8_t* block_value, uint32_t block_size);


#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_DATA_H
