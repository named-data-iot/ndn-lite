/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name-component.h"

int
name_component_tlv_decode(ndn_decoder_t* decoder, name_component_t* component)
{
  decoder_get_type(decoder, &component->type);
  decoder_get_length(decoder, &component->size);
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
name_component_compare(const name_component_t* a, const name_component_t* b)
{
  if (a->type != b->type) return -1;
  if (a->size != b->size) return -1;
  else {
    int result = memcmp(a->value, b->value, a->size);
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
