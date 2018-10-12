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
encoder_append_buffer_value(ndn_encoder_t* encoder, ndn_buffer_t* buffer)
{
  int rest_size = encoder->output->size - encoder->offset;
  if (rest_size != (int) buffer->size) {
    return -1;
  }
  memcpy(encoder->output->value + encoder->offset, buffer->value, buffer->size);
  return 0;
}
