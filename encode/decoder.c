/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "decoder.h"
#include <memory.h>

int
decoder_get_buffer_value(ndn_decoder_t* decoder, ndn_buffer_t* buffer)
{
  int rest_size = decoder->input->size - decoder->offset;
  if (rest_size != (int) buffer->size) {
    return -1;
  }
  memcpy(buffer->value, decoder->input->value + decoder->offset, buffer->size);
  return 0;
}
