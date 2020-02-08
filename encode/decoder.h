/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCODING_DECODER_H
#define NDN_ENCODING_DECODER_H

#include "encoder.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to keep the state when doing NDN TLV decoding.
 */
typedef struct ndn_decoder {
  /**
   * The encoded wire format buffer.
   */
  const uint8_t* input_value;
  /**
   * The size of the encoded wire format buffer.
   */
  uint32_t input_size;
  /**
   * The current offset after which the wire has not been decoded.
   */
  uint32_t offset;
} ndn_decoder_t;

/**
 * Init a decoder by setting the wire format buffer and its size.
 * @param decoder. Output. The decoder to be inited.
 * @param block_value. Input. The wire format buffer.
 * @param block_size. Input. The size of wire format buffer.
 */
static inline void
decoder_init(ndn_decoder_t* decoder, const uint8_t* block_value, uint32_t block_size)
{
  decoder->input_value = block_value;
  decoder->input_size = block_size;
  decoder->offset = 0;
}

/**
 * Get the variable size Type (T) and Length (L).
 * @param decoder. Input/Output. The decoder's offset will be updated.
 * @param var. Output. The uint32_t to keep the decoded Type (T) or Length (L).
 * @return 0 if there is no error.
 */
static inline int
decoder_get_var(ndn_decoder_t* decoder, uint32_t* var)
{
  uint8_t first_bit = decoder->input_value[decoder->offset];
  uint32_t rest_size = decoder->input_size - decoder->offset;
  if (first_bit < 253) {
    *var = first_bit;
    decoder->offset += 1;
  }
  else if (first_bit == 253 && rest_size >= 3) {
    *var = ((uint32_t)decoder->input_value[decoder->offset + 1] << 8)
      + decoder->input_value[decoder->offset + 2];
    decoder->offset += 3;
  }
  else if (first_bit == 254 && rest_size >= 5) {
    *var = ((uint32_t)decoder->input_value[decoder->offset + 1] << 24)
      + ((uint32_t)decoder->input_value[decoder->offset + 2] << 16)
      + ((uint32_t)decoder->input_value[decoder->offset + 3] << 8)
      + decoder->input_value[decoder->offset + 4];
    decoder->offset += 5;
  }
  else {
    return NDN_OVERSIZE_VAR;
  }
  return 0;
}

/**
 * Get the variable size Type (T).
 * @param decoder. Input/Output. The decoder's offset will be updated.
 * @param type. Output. The uint32_t to keep the decoded Type (T).
 * @return 0 if there is no error.
 */
static inline int
decoder_get_type(ndn_decoder_t* decoder, uint32_t* type)
{
  return decoder_get_var(decoder, type);
}

/**
 * Get the variable size Length (L).
 * This function is supposed to be invoked after decoder_get_type().
 * @param decoder. Input/Output. The decoder's offset will be updated.
 * @param length. Output. The uint32_t to keep the decoded Length (L).
 * @return 0 if there is no error.
 */
static inline int
decoder_get_length(ndn_decoder_t* decoder, uint32_t* length)
{
  return decoder_get_var(decoder, length);
}

/**
 * Get the variable size Value (V) to bytes.
 * This function is supposed to be invoked after decoder_get_length().
 * @param decoder. Input/Output. The decoder's offset will be updated.
 * @param value. Output. The variable to keep the value.
 *        It must have been initialized with an empty uint8_t array.
 * @param size. Input. The size should be set to the value obtained from decoder_get_length().
 * @return 0 if there is no error.
 */
static inline int
decoder_get_raw_buffer_value(ndn_decoder_t* decoder, uint8_t* value, uint32_t size)
{
  int rest_length = decoder->input_size - decoder->offset;
  if (rest_length < (int) size) {
    return NDN_OVERSIZE;
  }
  memcpy(value, decoder->input_value + decoder->offset, size);
  decoder->offset += size;
  return 0;
}

/**
 * Get the fixed size Value (V) to a single byte.
 * This function is supposed to be invoked after decoder_get_length().
 * @param decoder. Input/Output. The decoder's offset will be updated.
 * @param value. Output. The variable to keep the byte value.
 * @return 0 if there is no error.
 */
static inline int
decoder_get_byte_value(ndn_decoder_t* decoder, uint8_t* value)
{
  if (decoder->offset + 1 > decoder->input_size)
    return NDN_OVERSIZE;
  *value = decoder->input_value[decoder->offset];
  decoder->offset += 1;
  return 0;
}

/**
 * Get the fixed size Value (V) to a uint16_t.
 * This function is supposed to be invoked after decoder_get_length().
 * @param decoder. Input/Output. The decoder's offset will be updated.
 * @param value. Output. The variable to keep the uint16_t value.
 * @return 0 if there is no error.
 */
static inline int
decoder_get_uint16_value(ndn_decoder_t* decoder, uint16_t* value)
{
  if (decoder->offset + 2 > decoder->input_size)
    return NDN_OVERSIZE;

  *value = ((uint16_t)decoder->input_value[decoder->offset] << 8)
    + decoder->input_value[decoder->offset + 1];
  decoder->offset += 2;
  return 0;
}

/**
 * Get the fixed size Value (V) to a uint32_t.
 * This function is supposed to be invoked after decoder_get_length().
 * @param decoder. Input/Output. The decoder's offset will be updated.
 * @param value. Output. The variable to keep the uint32_t value.
 * @return 0 if there is no error.
 */
static inline int
decoder_get_uint32_value(ndn_decoder_t* decoder, uint32_t* value)
{
  if (decoder->offset + 4 > decoder->input_size)
    return NDN_OVERSIZE;
  *value = 0;
  for (int i = 0; i < 4; i++) {
    *value += (uint32_t)decoder->input_value[decoder->offset + i] << (8 * (3 - i));
  }
  decoder->offset += 4;
  return 0;
}

/**
 * Get the fixed size Value (V) to a uint64_t.
 * This function is supposed to be invoked after decoder_get_length().
 * @param decoder. Input/Output. The decoder's offset will be updated.
 * @param value. Output. The variable to keep the uint64_t value.
 * @return 0 if there is no error.
 */
static inline int
decoder_get_uint64_value(ndn_decoder_t* decoder, uint64_t* value)
{
  if (decoder->offset + 8 > decoder->input_size)
    return NDN_OVERSIZE;
  *value = 0;
  for (int i = 0; i < 8; i++) {
    *value += (uint64_t)decoder->input_value[decoder->offset + i] << (8 * (7 - i));
  }
  decoder->offset += 8;
  return 0;
}

/**
 * Get the non-negative int Value (V) to a uint64_t.
 * This function is supposed to be invoked after decoder_get_length().
 * TLV-LENGTH of the TLV element MUST be either 1, 2, 4, or 8.
 * @note For more details, go https://named-data.net/doc/NDN-packet-spec/current/tlv.html
 * @param decoder. Input/Output. The decoder's offset will be updated.
 * @param length. Input. The Length (L) obtained from decoder_get_length().
 * @param value. Output. The variable to keep the non-negative int value.
 * @return 0 if there is no error.
 */
static inline int
decoder_get_uint_value(ndn_decoder_t* decoder, uint32_t length, uint64_t* value)
{
  if (length == 1) {
    uint8_t temp_value = 0;
    decoder_get_byte_value(decoder, &temp_value);
    *value = (uint64_t)temp_value;
  }
  else if (length == 2) {
    uint16_t temp_value = 0;
    decoder_get_uint16_value(decoder, &temp_value);
    *value = (uint64_t)temp_value;
  }
  else if (length == 4) {
    uint32_t temp_value = 0;
    decoder_get_uint32_value(decoder, &temp_value);
    *value = (uint64_t)temp_value;
  }
  else if (length == 8) {
    decoder_get_uint64_value(decoder, value);
  }
  else {
    return NDN_WRONG_TLV_LENGTH;
  }
  return 0;
}

/**
 * Move the decoder's offset forward by @param step.
 * @param decoder. Output. The decoder's offset will be updated.
 * @param step. Input. The step by which the offset will be moved.
 * @return 0 if there is no error.
 */
static inline int
decoder_move_forward(ndn_decoder_t* decoder, uint32_t step)
{
  if (decoder->offset + step > decoder->input_size)
    return NDN_OVERSIZE;
  decoder->offset += step;
  return 0;
}

/**
 * Move the decoder's offset backward by @param step.
 * @param decoder. Output. The decoder's offset will be updated.
 * @param step. Input. The step by which the offset will be moved.
 * @return 0 if there is no error.
 */
static inline int
decoder_move_backward(ndn_decoder_t* decoder, uint32_t step)
{
  if (decoder->offset < step)
    return NDN_OVERSIZE;
  decoder->offset -= step;
  return 0;
}

/**
 * Get the offset of the decoder.
 * @param decoder. Input. The decoder's offset will be updated.
 * @return the uint32_t type offset.
 */
static inline uint32_t
decoder_get_offset(const ndn_decoder_t* decoder)
{
  return decoder->offset;
}

#ifdef __cplusplus
}
#endif
#endif // NDN_ENCODING_DECODER_H
