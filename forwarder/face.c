/*
 * Copyright (C) 2018 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "face.h"
#include "../encode/decoder.h"
#include "../encode/tlv.h"
#include "../encode/name.h"
#include "../encode/data.h"
#include "forwarder.h"

int
ndn_face_receive(ndn_face_t* self, const uint8_t* packet, uint32_t size)
{
  ndn_decoder_t decoder;
  uint32_t probe = 0;
  
  decoder_init(&decoder, packet, size);
  decoder_get_type(&decoder, &probe);
  if (probe == TLV_Data) {
    return forwarder_on_incoming_data(forwarder_get_instance(), self, NULL, packet, size);
  }
  else if (probe == TLV_Interest) {
    return forwarder_on_incoming_interest(forwarder_get_instance(), self, NULL, packet, size);
  }
  else {
    // ignore
  }
  return 0;
}
