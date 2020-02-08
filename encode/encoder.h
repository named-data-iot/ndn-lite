/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCODING_ENCODER_H
#define NDN_ENCODING_ENCODER_H

#include "../ndn-constants.h"
#include "../ndn-error-code.h"
#include "../ndn-enums.h"
#include <inttypes.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_buffer {
  uint8_t* value;
  uint32_t size;
  uint32_t max_size;
} ndn_buffer_t;

/**
 * The structure to keep the state when doing NDN TLV encoding.
 */
typedef struct ndn_encoder {
  /**
   * The buffer to keep the encoding output.
   */
  uint8_t* output_value;
  /**
   * The size of the buffer to keep the encoding output.
   */
  uint32_t output_max_size;
  /**
   * The actual size used of the buffer to keep the encoding output.
   */
  uint32_t offset;
} ndn_encoder_t;

/**
 * Init an encoder by setting the buffer to keep the encoding output and its size.
 * @param encoder. Output. The encoder to be inited.
 * @param block_value. Input. The buffer to keep the wire format buffer.
 * @param block_max_size. Input. The size of wire format buffer.
 */
static inline void
encoder_init(ndn_encoder_t* encoder, uint8_t* block_value, uint32_t block_max_size)
{
  memset(block_value, 0, block_max_size);
  encoder->output_value = block_value;
  encoder->output_max_size = block_max_size;
  encoder->offset = 0;
}

/**
 * Probe the size of a variable-length type (T) or length (L).
 * @param var. Input. The value of the variable-length type (T) or length (L).
 * @return the length of the type (T) or length (L).
 */
static inline uint32_t
encoder_get_var_size(uint32_t var)
{
  if (var < 253) return 1;
  if (var <= 0xFFFF) return 3;
  return 5;
}

/**
 * Probe the size of a TLV block.
 * This function is used to check whether the output buffer size is large enough.
 * @param type. Input. The value of the type (T).
 * @param payload_size. Input. The value of length (L).
 * @return the length of the TLV block.
 */
static inline uint32_t
encoder_probe_block_size(uint32_t type, uint32_t payload_size)
{
  uint32_t type_size = encoder_get_var_size(type);
  uint32_t length_size = encoder_get_var_size(payload_size);
  return payload_size + type_size + length_size;
}

/**
 * Append a variable-length type (T) or length (L) to the wire format buffer.
 * @param encoder. Output. The encoder will keep the encoding result and the offset will be updated.
 * @param var. Input. The variable-length type (T) or length (L).
 * @return 0 if there is no error.
 */
static inline int
encoder_append_var(ndn_encoder_t* encoder, uint32_t var)
{
  uint32_t rest_size = encoder->output_max_size - encoder->offset;
  if (var < 253 && rest_size >= 1) {
    encoder->output_value[encoder->offset] = var & 0xFF;
    encoder->offset += 1;
  }
  else if (var <= 0xFFFF && rest_size >= 3) {
    encoder->output_value[encoder->offset] = 253;
    encoder->output_value[encoder->offset + 1] = (var >> 8) & 0xFF;
    encoder->output_value[encoder->offset + 2] = var & 0xFF;
    encoder->offset += 3;
  }
  else if (var <= 0xFFFFFFFF && rest_size >= 5) {
    encoder->output_value[encoder->offset] = 254;
    encoder->output_value[encoder->offset + 1] = (var >> 24) & 0xFF;
    encoder->output_value[encoder->offset + 2] = (var >> 16) & 0xFF;
    encoder->output_value[encoder->offset + 3] = (var >> 8) & 0xFF;
    encoder->output_value[encoder->offset + 4] = var & 0xFF;
    encoder->offset += 5;
  }
  else {
    return NDN_OVERSIZE_VAR;
  }
  return 0;
}

/**
 * Append a variable-length type (T) to the wire format buffer.
 * @param encoder. Output. The encoder will keep the encoding result and the offset will be updated.
 * @param type. Input. The variable-length type (T).
 * @return 0 if there is no error.
 */
static inline int
encoder_append_type(ndn_encoder_t* encoder, uint32_t type)
{
  return encoder_append_var(encoder, type);
}

/**
 * Append a variable-length length (L) to the wire format buffer.
 * @param encoder. Output. The encoder will keep the encoding result and the offset will be updated.
 * @param length. Input. The variable-length length (L).
 * @return 0 if there is no error.
 */
static inline int
encoder_append_length(ndn_encoder_t* encoder, uint32_t length)
{
  return encoder_append_var(encoder, length);
}

/**
 * Append the byte array as the value (V) to the wire format buffer.
 * @param encoder. Output. The encoder will keep the encoding result and the offset will be updated.
 * @param buffer. Input. The buffer to be encoded.
 * @param size. Input. The size of the buffer to be encoded.
 * @return 0 if there is no error.
 */
static inline int
encoder_append_raw_buffer_value(ndn_encoder_t* encoder, const uint8_t* buffer, uint32_t size)
{
  int rest_length = encoder->output_max_size - encoder->offset;
  if (rest_length < (int) size) {
    return NDN_OVERSIZE;
  }
  memcpy(encoder->output_value + encoder->offset, buffer, size);
  encoder->offset += size;
  return 0;
}

/**
 * Append a single byte as the value (V) to the wire format buffer.
 * @param encoder. Output. The encoder will keep the encoding result and the offset will be updated.
 * @param value. Input. The byte to be encoded.
 * @return 0 if there is no error.
 */
static inline int
encoder_append_byte_value(ndn_encoder_t* encoder, uint8_t value)
{
  if (encoder->offset + 1 > encoder->output_max_size)
    return NDN_OVERSIZE;
  encoder->output_value[encoder->offset] = value;
  encoder->offset += 1;
  return 0;
}

/**
 * Append a uint16_t as the value (V) to the wire format buffer.
 * @param encoder. Output. The encoder will keep the encoding result and the offset will be updated.
 * @param value. Input. The uint16_t to be encoded.
 * @return 0 if there is no error.
 */
static inline int
encoder_append_uint16_value(ndn_encoder_t* encoder, uint16_t value)
{
  if (encoder->offset + 2 > encoder->output_max_size)
    return NDN_OVERSIZE;
  encoder->output_value[encoder->offset] = (value >> 8) & 0xFF;
  encoder->output_value[encoder->offset + 1] = value & 0xFF;
  encoder->offset += 2;
  return 0;
}

/**
 * Append a uint32_t as the value (V) to the wire format buffer.
 * @param encoder. Output. The encoder will keep the encoding result and the offset will be updated.
 * @param value. Input. The uint32_t to be encoded.
 * @return 0 if there is no error.
 */
static inline int
encoder_append_uint32_value(ndn_encoder_t* encoder, uint32_t value)
{
  if (encoder->offset + 4 > encoder->output_max_size)
    return NDN_OVERSIZE;
  for (int i = 0; i < 4; i++) {
    encoder->output_value[encoder->offset + i] = (value >> (8 * (3 - i))) & 0xFF;
  }
  encoder->offset += 4;
  return 0;
}

/**
 * Append a uint64_t as the value (V) to the wire format buffer.
 * @param encoder. Output. The encoder will keep the encoding result and the offset will be updated.
 * @param value. Input. The uint64_t to be encoded.
 * @return 0 if there is no error.
 */
static inline int
encoder_append_uint64_value(ndn_encoder_t* encoder, uint64_t value)
{
  if (encoder->offset + 8 > encoder->output_max_size)
    return NDN_OVERSIZE;
  for (int i = 0; i < 8; i++) {
    encoder->output_value[encoder->offset + i] = (value >> (8 * (7 - i))) & 0xFF;
  }
  encoder->offset += 8;
  return 0;
}

/**
 * Probe the length of a non-negative int as the value (V).
 * TLV-LENGTH of the TLV element MUST be either 1, 2, 4, or 8.
 * @note For more details, go https://named-data.net/doc/NDN-packet-spec/current/tlv.html
 * @param value. Input. The uint to be checked.
 * @return the length of a non-negative int.
 */
static inline int
encoder_probe_uint_length(uint64_t value)
{
  if (value <= 255) {
    return 1;
  }
  else if (value <= 0xFFFF) {
    return 2;
  }
  else if (value <= 0xFFFFFFFF) {
    return 4;
  }
  else {
    return 8;
  }
}

/**
 * Append a non-negative int as the value (V) to the wire format buffer.
 * TLV-LENGTH of the TLV element MUST be either 1, 2, 4, or 8.
 * @note For more details, go https://named-data.net/doc/NDN-packet-spec/current/tlv.html
 * @param encoder. Output. The encoder will keep the encoding result and the offset will be updated.
 * @param value. Input. The uint to be encoded.
 * @return 0 if there is no error.
 */
static inline int
encoder_append_uint_value(ndn_encoder_t* encoder, uint64_t value)
{
  if (value <= 255) {
    return encoder_append_byte_value(encoder, (uint8_t)value);
  }
  else if (value <= 0xFFFF) {
    return encoder_append_uint16_value(encoder, (uint16_t)value);
  }
  else if (value <= 0xFFFFFFFF) {
    return encoder_append_uint32_value(encoder, (uint32_t)value);
  }
  else {
    return encoder_append_uint64_value(encoder, value);
  }
}

/**
 * Move the encoder's offset forward by @param step.
 * @param encoder. Output. The encoder whose offset will be updated.
 * @param step. Input. The step by which the offset will be moved.
 * @return 0 if there is no error.
 */
static inline int
encoder_move_forward(ndn_encoder_t* encoder, uint32_t step)
{
  if (encoder->offset + step > encoder->output_max_size)
    return NDN_OVERSIZE;
  encoder->offset += step;
  return 0;
}

/**
 * Move the encoder's offset backward by @param step.
 * @param encoder. Output. The encoder whose offset will be updated.
 * @param step. Input. The step by which the offset will be moved.
 * @return 0 if there is no error.
 */
static inline int
encoder_move_backward(ndn_encoder_t* encoder, uint32_t step)
{
  encoder->offset -= step;
  return 0;
}

/**
 * Get the offset of the encoder.
 * @param encoder. Input. The encoder's offset will be updated.
 * @return the uint32_t type offset.
 */
static inline uint32_t
encoder_get_offset(const ndn_encoder_t* encoder)
{
  return encoder->offset;
}

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_ENCODER_H
