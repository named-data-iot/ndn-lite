/*
 * Copyright (C) 2018 Regents of the University of California.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NDN_ENCODING_INTEREST_H
#define NDN_ENCODING_INTEREST_H

#include "name.h"
#include <string.h>

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


// this function is NOT recommended
// to save the memory, it's recommended to create a Data first and init each
// of its member attribute
static inline int
ndn_data_init(ndn_data_t* data, const ndn_name_t* name, const metainfo* metainfo,
              uint8_t* content_value, uint32_t content_size)
{
  data->name = &name;
  data->metainfo = metainfo;
  if (content_size < NDN_CONTENT_BUFFER_SIZE) {
    memcpy(data->content_value, content_value, content_size);
  }
}

// int
// ndn_data_from_block(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size);

// int
// ndn_data_ec_sign(ndn_data_t* data, const uint8_t* prv_key_value, uint32_t prv_key_size);

// int
// ndn_data_hmac_sign(ndn_data_t* data, const uint8_t* prv_key_value, uint32_t prv_key_size);

// int
// ndn_data_verify(ndn_data_t* data);

// int
// ndn_data_encode(const ndn_data_t* data, uint8_t* block_value, uint32_t block_max_size);


#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_INTEREST_H
