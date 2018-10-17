/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef ENCODING_NAME_H
#define ENCODING_NAME_H

#include "tlv.h"
#include "encoder.h"
#include "decoder.h"
#include "ndn_constants.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct name_component {
  uint32_t type;
  uint8_t value[NAME_COMPONENT_BUFFER_SIZE];
  uint32_t size;
} name_component_t;

typedef struct name_component_block {
  uint8_t value[NAME_COMPONENT_BLOCK_SIZE];
  uint32_t size;
} name_component_block_t;

typedef struct ndn_name {
  name_component_t components[NDN_NAME_COMPONENTS_SIZE];
  uint32_t components_size;
} ndn_name_t;

// the function will do memory copy
static inline int
name_component_from_buffer(name_component_t* component, uint32_t type, uint8_t* value, uint32_t size)
{
  if (size > NAME_COMPONENT_BUFFER_SIZE)
    return NDN_ERROR_OVERSIZE;
  component->type = type;
  memcpy(component->value, value, size);
  component->size = size;
  return 0;
}

// the function will do memory copy
// please include the last byte of the string, which is \0
static inline int
name_component_from_string(name_component_t* component, char* string, uint32_t size)
{
  return name_component_from_buffer(component, TLV_GenericNameComponent, (uint8_t*)string, size - 1);
}

// the function will do memory copy
int
name_component_from_block(name_component_t* component, name_component_block_t* block);

// return 0 if two components are the same
int
name_component_compare(name_component_t* a, name_component_t* b);

static inline int
name_component_probe_block_size(name_component_t* component)
{
  return encoder_probe_block_size(component->type, component->size);
}

int
name_component_tlv_encode(ndn_encoder_t* encoder, name_component_t* component);

// will do memory copy
int
ndn_name_init(ndn_name_t *name, name_component_t* components, uint32_t size);

// will do memory copy
int
ndn_name_append_component(ndn_name_t *name, name_component_t* component);

// will do memory copy
// support regular string; not support URI
int
ndn_name_from_string(ndn_name_t *name, char* string, uint32_t size);

static inline uint32_t
ndn_name_probe_block_size(ndn_name_t *name)
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
ndn_name_tlv_encode(ndn_encoder_t* encoder, ndn_name_t *name);

#ifdef __cplusplus
}
#endif

#endif // ENCODING_NAME_H
