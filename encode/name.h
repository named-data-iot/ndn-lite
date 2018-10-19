/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_NAME_H
#define NDN_ENCODING_NAME_H

#include "name-component.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_name {
  name_component_t components[NDN_NAME_COMPONENTS_SIZE];
  uint32_t components_size;
} ndn_name_t;

// will do memory copy
int
ndn_name_init(ndn_name_t *name, const name_component_t* components, uint32_t size);

int
ndn_name_tlv_decode(ndn_decoder_t* decoder, ndn_name_t* name);

int
ndn_name_from_block(ndn_name_t* name, const uint8_t* block_value, uint32_t block_size);

// will do memory copy
int
ndn_name_append_component(ndn_name_t *name, const name_component_t* component);

// will do memory copy
// support regular string; not support URI
int
ndn_name_from_string(ndn_name_t *name, const char* string, uint32_t size);

static inline uint32_t
ndn_name_probe_block_size(const ndn_name_t *name)
{
  uint32_t value_size = 0;
  for (uint32_t i = 0; i < name->components_size; i++) {
    value_size += name_component_probe_block_size(&name->components[i]);
  }
  return encoder_probe_block_size(TLV_Name, value_size);
}

// will do memory copy
// need to call ndn_name_probe_block_size to initialize output block in advance
int
ndn_name_tlv_encode(ndn_encoder_t* encoder, const ndn_name_t *name);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_NAME_H
