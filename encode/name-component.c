/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name-component.h"

int
name_component_tlv_decode(ndn_decoder_t* decoder, name_component_t* component)
{
  uint32_t probe = 0;
  decoder_get_type(decoder, &component->type);
  decoder_get_length(decoder, &probe);
  if (probe > NDN_NAME_COMPONENT_BUFFER_SIZE) {
    return NDN_OVERSIZE;
  }
  component->size = probe;
  return decoder_get_raw_buffer_value(decoder, component->value, component->size);
}

int
name_component_from_block(name_component_t* component, const name_component_block_t* block)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block->value, block->size);
  return name_component_tlv_decode(&decoder, component);
}

int
name_component_compare(const name_component_t* lhs, const name_component_t* rhs)
{
  if (lhs->type != rhs->type) return -1;
  if (lhs->size != rhs->size) return -1;
  else {
    int result = memcmp(lhs->value, rhs->value, lhs->size);
    if (result != 0) return -1;
    else return 0;
  }
}

int
name_component_tlv_encode(ndn_encoder_t* encoder, const name_component_t* component)
{
  encoder_append_type(encoder, component->type);
  encoder_append_length(encoder, component->size);
  return encoder_append_raw_buffer_value(encoder, component->value, component->size);
}
