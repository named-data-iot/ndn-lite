/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name.h"
#include <stdio.h>

int
name_component_from_block(name_component_t* component, name_component_block_t* block)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block->value, block->size);
  decoder_get_type(&decoder, &component->type);
  decoder_get_length(&decoder, &component->size);
  decoder_get_raw_buffer_value(&decoder, component->value, component->size);
  return 0;
}

int
name_component_compare(name_component_t* a, name_component_t* b)
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
name_component_tlv_encode(ndn_encoder_t* encoder, name_component_t* component)
{
  encoder_append_type(encoder, component->type);
  encoder_append_length(encoder, component->size);
  return encoder_append_raw_buffer_value(encoder, component->value, component->size);
}


int
ndn_name_init(ndn_name_t *name, name_component_t* components, uint32_t size)
{
  if (size <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(name->components, components, size * sizeof(name_component_t));
    name->components_size = size;
    return 0;
  }
  else
    return -1;
}

int
ndn_name_append_component(ndn_name_t *name, name_component_t* component)
{
  if (name->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(name->components + name->components_size, component, sizeof(name_component_t));
    name->components_size++;
    return 0;
  }
  else
    return NDN_ERROR_OVERSIZE;
}

int
ndn_name_from_string(ndn_name_t *name, char* string, uint32_t size)
{
  name->components_size = 0;

  uint32_t i = 0;
  uint32_t last_divider = 0;
  if (string[i] != '/') {
    return NDN_ERROR_NAME_INVALID_FORMAT;
  }
  ++i;
  while (i < size) {
    if (string[i] == '/') {
      name_component_t component;
      name_component_from_string(&component, &string[last_divider + 1], i - last_divider - 1);
      int result = ndn_name_append_component(name, &component);
      if (result < 0) {
        return result;
      }
      last_divider = i;
    }
    ++i;
  }
  return 0;
}

int
ndn_name_tlv_encode(ndn_encoder_t* encoder, ndn_name_t *name)
{
  int block_sizes[name->components_size];
  encoder_append_type(encoder, TLV_Name);
  size_t value_size = 0;
  for (size_t i = 0; i < name->components_size; i++) {
    block_sizes[i] = name_component_probe_block_size(&name->components[i]);
    value_size += block_sizes[i];
  }
  encoder_append_length(encoder, value_size);

  for (size_t i = 0; i < name->components_size; i++) {
    int result = name_component_tlv_encode(encoder, &name->components[i]);
    if (result < 0)
      return result;
  }
  return 0;
}
