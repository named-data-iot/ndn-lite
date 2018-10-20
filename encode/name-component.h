/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_NAME_COMPONENT_H
#define NDN_ENCODING_NAME_COMPONENT_H

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

// the function will do memory copy
static inline int
name_component_from_buffer(name_component_t* component, uint32_t type,
                           const uint8_t* value, uint32_t size)
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
name_component_from_string(name_component_t* component, const char* string, uint32_t size)
{
  if (string[size - 1] == '\0')
    return name_component_from_buffer(component, TLV_GenericNameComponent,
                                      (uint8_t*)string, size - 1);
  else
    return name_component_from_buffer(component, TLV_GenericNameComponent,
                                      (uint8_t*)string, size);
}

int
name_component_tlv_decode(ndn_decoder_t* decoder, name_component_t* component);

// the function will do memory copy
int
name_component_from_block(name_component_t* component, const name_component_block_t* block);

// return 0 if two components are the same
int
name_component_compare(const name_component_t* a, const name_component_t* b);

static inline int
name_component_probe_block_size(const name_component_t* component)
{
  return encoder_probe_block_size(component->type, component->size);
}

int
name_component_tlv_encode(ndn_encoder_t* encoder, const name_component_t* component);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_NAME_COMPONENT_H
