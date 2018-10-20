/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "encoder.h"
#include <memory.h>

int
encoder_append_buffer_value(ndn_encoder_t* encoder, const ndn_buffer_t* buffer)
{
  int rest_size = encoder->output_max_size - encoder->offset;
  if (rest_size < (int) buffer->size) {
    return NDN_ERROR_OVERSIZE;
  }
  memcpy(encoder->output_value + encoder->offset, buffer->value, buffer->size);
  encoder->offset += buffer->size;
  return 0;
}

int
encoder_append_raw_buffer_value(ndn_encoder_t* encoder, const uint8_t* buffer, uint32_t size)
{
  int rest_size = encoder->output_max_size - encoder->offset;
  if (rest_size < (int) size) {
    return NDN_ERROR_OVERSIZE;
  }
  memcpy(encoder->output_value + encoder->offset, buffer, size);
  encoder->offset += size;
  return 0;
}
