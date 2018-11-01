/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name.h"

int
ndn_name_init(ndn_name_t *name, const name_component_t* components, uint32_t size)
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
ndn_name_tlv_decode(ndn_decoder_t* decoder, ndn_name_t* name)
{
  uint32_t type = 0;
  decoder_get_type(decoder, &type);
  if (type != TLV_Name) {
    return NDN_ERROR_WRONG_TLV_TYPE;
  }
  uint32_t length = 0;
  decoder_get_length(decoder, &length);
  uint32_t start_offset = decoder->offset;
  int counter = 0;
  while (decoder->offset < start_offset + length) {
    uint32_t comp_type = 0;
    decoder_get_type(decoder, &comp_type);
    name->components[counter].type = comp_type;
    if (!(name->components[counter].type == TLV_GenericNameComponent
          || name->components[counter].type == TLV_ImplicitSha256DigestComponent
          || name->components[counter].type == TLV_ParametersSha256DigestComponent)) {
      return NDN_ERROR_WRONG_TLV_TYPE;
    }
    decoder_get_length(decoder, &name->components[counter].size);
    int result = decoder_get_raw_buffer_value(decoder, name->components[counter].value,
                                              name->components[counter].size);
    if (result < 0) {
      return result;
    }
    ++counter;
  }
  name->components_size = counter;
  return 0;
}

int
ndn_name_from_block(ndn_name_t* name, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  return ndn_name_tlv_decode(&decoder, name);
}

int
ndn_name_append_component(ndn_name_t *name, const name_component_t* component)
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
ndn_name_from_string(ndn_name_t *name, const char* string, uint32_t size)
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
    if (i == size - 1) {
      name_component_t component;
      name_component_from_string(&component, &string[last_divider + 1], i - last_divider);
      int result = ndn_name_append_component(name, &component);
      if (result < 0) {
        return result;
      }
    }
    ++i;
  }
  return 0;
}

int
ndn_name_tlv_encode(ndn_encoder_t* encoder, const ndn_name_t *name)
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
