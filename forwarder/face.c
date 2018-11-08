/*
 * Copyright (C) 2018 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "face.h"

int
ndn_face_receive(ndn_face_t* self, const uint8_t* packet, uint32_t size)
{
  (void)self;

  ndn_decoder_t decoder;
  decoder_init(&decoder, &packet[9], size);
  uint32_t probe = 0;
  decoder_get_type(&decoder, &probe);
  if (probe == TLV_Data) {
    decoder_get_length(&decoder, &probe);
    ndn_name_t data_name;
    ndn_name_tlv_decode(&decoder, &data_name);
    // check against PIT and trigger callbacks
  }
  else if (probe == TLV_Interest) {
    // TBD
  }
  else {
    // ignore
  }
  return 0;
}
