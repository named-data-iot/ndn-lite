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

#include "signature.h"
#include "../security/crypto-key.h"
#include "metainfo.h"

#ifdef __cplusplus
extern "C" {
#endif

// the best practice of Data is to first declare a ndn_data_t object and
// init each component using object.attribute_name to save memory

typedef struct ndn_data {
  ndn_name_t name;
  ndn_metainfo_t metainfo;
  uint8_t content_value[NDN_CONTENT_BUFFER_SIZE];
  uint32_t content_size;
  ndn_signature_t signature;
} ndn_data_t;

static inline int
ndn_data_init(ndn_data_t* data, uint8_t* content_value, uint32_t content_size)
{
  if (content_size < NDN_CONTENT_BUFFER_SIZE) {
    memcpy(data->content_value, content_value, content_size);
    data->content_size = content_size;
  }
  return 0;
}

// this function should be invoked only after data's signature
// info (including signature.sig_size) has been initialized
static inline uint32_t
ndn_data_probe_block_size(const ndn_data_t* data)
{
  // name
  uint32_t data_buffer_size = ndn_name_probe_block_size(&data->name);
  // meta info
  data_buffer_size += ndn_metainfo_probe_block_size(&data->metainfo);
  // content
  data_buffer_size += encoder_probe_block_size(TLV_Content, data->content_size);
  // signature info
  data_buffer_size += ndn_signature_info_probe_block_size(&data->signature);
  // signature value
  data_buffer_size += ndn_signature_value_probe_block_size(&data->signature);

  return encoder_probe_block_size(TLV_Data, data_buffer_size);
}

// this function should be invoked only after data's signature
// info has been initialized
int
ndn_data_prepare_unsigned_block(ndn_encoder_t* encoder, const ndn_data_t* data);

// this function will automatically set signature info and signature value
int
ndn_data_tlv_encode_digest_sign(ndn_encoder_t* encoder, ndn_data_t* data);

// this function will automatically set signature info and signature value
int
ndn_data_tlv_encode_ecdsa_sign(ndn_encoder_t* encoder, ndn_data_t* data,
                               const ndn_name_t* producer_identity, const ndn_ecc_prv_t* prv_key);

// this function will automatically set signature info and signature value
int
ndn_data_tlv_encode_hmac_sign(ndn_encoder_t* encoder, ndn_data_t* data,
                              const ndn_name_t* producer_identity, const ndn_hmac_key_t* hmac_key);

int
ndn_data_tlv_decode_no_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size);

int
ndn_data_tlv_decode_digest_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size);

int
ndn_data_tlv_decode_ecdsa_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                                 const ndn_ecc_pub_t* pub_key);

int
ndn_data_tlv_decode_hmac_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                                const ndn_hmac_key_t* hmac_key);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_DATA_H
