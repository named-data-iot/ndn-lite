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
#include "metainfo.h"
#include "../security/crypto-key.h"

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

static inline int
ndn_data_set_content(ndn_data_t* data, uint8_t* content_value, uint32_t content_size)
{
  if (content_size < NDN_CONTENT_BUFFER_SIZE) {
    memcpy(data->content_value, content_value, content_size);
    data->content_size = content_size;
  }
  return 0;
}

// for content encrypted data
// call this function before data encode/sign. Using aes cbc, without padding
int
ndn_data_set_encrypted_content(ndn_data_t* data,
                               const uint8_t* content_value, uint32_t content_size,
                               const ndn_name_t* key_id, const uint8_t* aes_iv,
                               const ndn_aes_key_t* key);

// call this function after data decode/verify. Using aes cbc, without padding
int
ndn_data_parse_encrypted_content(ndn_data_t* data,
                                 uint8_t* content_value, uint32_t* content_used_size,
                                 ndn_name_t* key_id, uint8_t* aes_iv, ndn_aes_key_t* key);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_DATA_H
