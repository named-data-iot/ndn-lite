/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_ENCODER_H
#define NDN_ENCODING_ENCODER_H

#include "block.h"
#include "ndn_constants.h"

#ifdef __cplusplus
extern "C" {
#endif

// State keeper when doing encode
typedef struct ndn_encoder {
  uint8_t* output_value;
  uint32_t output_max_size;
  uint32_t offset;
} ndn_encoder_t;

// only used for type (T) and length (L)
static inline int
encoder_get_var_size(uint32_t var)
{
  if (var < 253) return 1;
  if (var <= 0xFFFF) return 3;
  else return 5;
}

// get the TLV block size before create the block
// use this function to avoid malloc or other dynamic mem operations
static inline uint32_t
encoder_probe_block_size(const int type, const uint32_t payload_size)
{
  uint32_t type_size = encoder_get_var_size(type);
  uint32_t length_size = encoder_get_var_size(payload_size);
  return (payload_size + type_size + length_size);
}

// init an encoder
// To invoke the function, first probe the size of the output block size and
// create the block
static inline void
encoder_init(ndn_encoder_t* encoder, uint8_t* block_value, uint32_t block_max_size)
{
  encoder->output_value = block_value;
  encoder->output_max_size = block_max_size;
  encoder->offset = 0;
}

// function to set the type (T) and length (L)
static inline int
encoder_append_var(ndn_encoder_t* encoder, uint32_t var)
{
  size_t rest_size = encoder->output_max_size - encoder->offset;
  if (var < 253) {
    encoder->output_value[encoder->offset] = var & 0xFF;
    encoder->offset += 1;
  }
  else if (var <= 0xFFFF && rest_size >= 3) {
    encoder->output_value[encoder->offset] = 253;
    encoder->output_value[encoder->offset + 1] = (var >> 8) & 0xFF;
    encoder->output_value[encoder->offset + 2] = var & 0xFF;
    encoder->offset += 3;
  }
  else if (rest_size >= 5) {
    encoder->output_value[encoder->offset] = 254;
    encoder->output_value[encoder->offset + 1] = (var >> 24) & 0xFF;
    encoder->output_value[encoder->offset + 2] = (var >> 16) & 0xFF;
    encoder->output_value[encoder->offset + 3] = (var >> 8) & 0xFF;
    encoder->output_value[encoder->offset + 4] = var & 0xFF;
    encoder->offset += 5;
  }
  else {
    return NDN_ERROR_OVERSIZE_VAR;
  }
  return 0;
}

static inline int
encoder_append_integer(ndn_encoder_t* encoder, uint32_t var){
  return encoder_append_var(encoder, var);
}

// function to set the type (T)
static inline int
encoder_append_type(ndn_encoder_t* encoder, uint32_t type)
{
  return encoder_append_var(encoder, type);
}

// function to set the length (L)
static inline int
encoder_append_length(ndn_encoder_t* encoder, uint32_t length)
{
  return encoder_append_var(encoder, length);
}

// function to set the value (V)
// the buffer size must be equal to the rest size of the output maintained by
// the encoder
int
encoder_append_buffer_value(ndn_encoder_t* encoder, const ndn_buffer_t* buffer);

int
encoder_append_raw_buffer_value(ndn_encoder_t* encoder, const uint8_t* buffer, uint32_t size);

static inline int
encoder_append_byte_value(ndn_encoder_t* encoder, uint8_t value)
{
  if (encoder->offset + 1 > encoder->output_max_size)
    return NDN_ERROR_OVERSIZE;
  encoder->output_value[encoder->offset] = value;
  encoder->offset += 1;
  return 0;
}

static inline int
encoder_move_forward(ndn_encoder_t* encoder, uint32_t step){
  if (encoder->offset + step > encoder->output_max_size)
  return NDN_ERROR_OVERSIZE;
  encoder->offset += step;
  return 0;
}

static inline int
encoder_move_backward(ndn_encoder_t* encoder, uint32_t step){
  encoder->offset -= step;
  return 0;
}

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_ENCODER_H
