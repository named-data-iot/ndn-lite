/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NDN_ENCODING_NAME_COMPONENT_H
#define NDN_ENCODING_NAME_COMPONENT_H

#include "tlv.h"
#include "decoder.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to represent the Name Component.
 */
typedef struct name_component {
  /**
   * The component type.
   */
  uint32_t type;
  /**
   * The value which name component holds. (not include T and L)
   */
  uint8_t value[NDN_NAME_COMPONENT_BUFFER_SIZE];
  /**
   * The size of component value buffer.
   */
  uint8_t size;
} name_component_t;

/**
 * The structure to represent the wire format name component block.
 */
typedef struct name_component_block {
  /**
   * Name component TLV block.
   */
  uint8_t value[NDN_NAME_COMPONENT_BLOCK_SIZE];
  /**
   * The size of block.
   */
  uint8_t size;
} name_component_block_t;

/**
 * Init a Name Component structure.
 * @param component. Output. The Name Component structure to be inited.
 * @param type. Input. Name Component Type to be set with.
 */
static inline void
name_component_init(name_component_t* component, uint32_t type)
{
  component->type = type;
  if (type == TLV_ImplicitSha256DigestComponent || type == TLV_ParametersSha256DigestComponent) {
    component->size = 32;
  }
}

/**
 * Init a Name Component structure from caller supplied memory block.
 * The function will do memory copy
 * @param component. Output. The Name Component structure to be inited.
 * @param type. Input. Name Component Type to be set with.
 * @param value. Input. Memory block which holds the Name Component Value.
 * @param size. Input. Size of input block.
 * @return 0 if there is no error.
 */
static inline int
name_component_from_buffer(name_component_t* component, uint32_t type,
                           const uint8_t* value, uint32_t size)
{
  if (size > NDN_NAME_COMPONENT_BUFFER_SIZE)
    return NDN_OVERSIZE;
  component->type = type;
  memcpy(component->value, value, size);
  component->size = size;
  return 0;
}

/**
 * Init a Name Component structure from string. Please include the last byte of the string,
 * which is "\0". The function will do memory copy.
 * @param component. Output. The Name Component structure to be inited.
 * @param string. Input. String variable which name component initing from.
 * @param size. Input. Size of input string.
 * @return 0 if there is no error.
 */
static inline int
name_component_from_string(name_component_t* component, const char* string, uint32_t size)
{
  if (string[size - 1] == '\0')
    return name_component_from_buffer(component, TLV_GenericNameComponent,
                                      (const uint8_t*)string, size - 1);
  else
    return name_component_from_buffer(component, TLV_GenericNameComponent,
                                      (const uint8_t*)string, size);
}

/**
 * Decode the Name Component from wire format (TLV block).
 * @param decoder. Input. The decoder who keeps the decoding result and the state.
 * @param component. Output. The Name Component decoded from TLV block.
 * @return 0 if there is no error.
 */
int
name_component_tlv_decode(ndn_decoder_t* decoder, name_component_t* component);

/**
 * Decode an Name Component TLV block into an Name Component. This function will do memory copy.
 * @param component. Output. The component to which the TLV block will be decoded.
 * @param block. Input. The Name Component TLV.
 * @return 0 if decoding is successful.
 */
int
name_component_from_block(name_component_t* component, const name_component_block_t* block);

/**
 * Compare two name components.
 * @param lhs. Input. Left-hand-side name component.
 * @param rhs. Input. Right-hand-side name component.
 * @return 0 if @p lhs == @p rhs.
 */
int
name_component_compare(const name_component_t* lhs, const name_component_t* rhs);

/**
 * Probe the size of a Name component TLV block before encoding it from a Name Component structure.
 * This function is used to check whether the output buffer size is enough or not.
 * @param component. Input. The name component structure to be probed.
 * @return the length of the expected name component TLV block.
 */
static inline uint32_t
name_component_probe_block_size(const name_component_t* component)
{
  return encoder_probe_block_size(component->type, component->size);
}

/**
 * Encode the Name Component structure into wire format (TLV block).
 * @param encoder. Output. The encoder who keeps the encoding result and the state.
 * @param component. Input. The Name Component structure to be encoded.
 * @return 0 if there is no error.
 */
int
name_component_tlv_encode(ndn_encoder_t* encoder, const name_component_t* component);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_NAME_COMPONENT_H
