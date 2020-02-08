/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "encrypted-payload.h"
#include "tlv.h"
#include "encoder.h"
#include "decoder.h"
#include "key-storage.h"
#include "../security/ndn-lite-aes.h"
#include "../security/ndn-lite-rng.h"

int
ndn_probe_encrypted_payload_length(uint32_t input_size)
{
  return encoder_probe_block_size(TLV_AC_AES_IV, NDN_AES_BLOCK_SIZE)
         + encoder_probe_block_size(TLV_AC_ENCRYPTED_PAYLOAD, ndn_aes_probe_padding_size(input_size) + NDN_AES_BLOCK_SIZE);
}

int
ndn_gen_encrypted_payload(const uint8_t* input, uint32_t input_size, uint8_t* output, uint32_t* used_size,
                          uint32_t aes_key_id, const uint8_t* iv, uint32_t iv_size)
{
  int ret_val = -1;
  *used_size = 0;
  // probe the length of result
  *used_size += encoder_probe_block_size(TLV_AC_AES_IV, NDN_AES_BLOCK_SIZE);
  *used_size += encoder_probe_block_size(TLV_AC_ENCRYPTED_PAYLOAD, ndn_aes_probe_padding_size(input_size));

  // prepare output block
  memset(output, 0, *used_size);
  ndn_encoder_t encoder;
  encoder_init(&encoder, output, *used_size);

  // get key
  ndn_aes_key_t* key = ndn_key_storage_get_aes_key(aes_key_id);
  if (key == NULL) {
    return NDN_AC_KEY_NOT_FOUND;
  }

  // type: TLV_AES_IV
  ret_val = encoder_append_type(&encoder, TLV_AC_AES_IV);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(&encoder, NDN_AES_BLOCK_SIZE);
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint8_t* iv_start = encoder.output_value + encoder.offset;
  if (iv != NULL || iv_size >= NDN_AES_BLOCK_SIZE) {
    ret_val = encoder_append_raw_buffer_value(&encoder, iv, NDN_AES_BLOCK_SIZE);
  }
  else {
    ret_val = ndn_rng(iv_start, NDN_AES_BLOCK_SIZE);
    encoder.offset += NDN_AES_BLOCK_SIZE;
  }
  if (ret_val != NDN_SUCCESS) return ret_val;

  // type: ENCRYPTED PAYLOAD
  ret_val = encoder_append_type(&encoder, TLV_AC_ENCRYPTED_PAYLOAD);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(&encoder, ndn_aes_probe_padding_size(input_size));
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint32_t encryption_used_size = 0;
  ret_val = ndn_aes_cbc_encrypt(input, input_size, encoder.output_value + encoder.offset, &encryption_used_size,
                                iv_start, key);
  if (ret_val != NDN_SUCCESS) return ret_val;
  return 0;
}

int
ndn_parse_encrypted_payload(const uint8_t* input, uint32_t input_size,
                            uint8_t* output, uint32_t* output_size, uint32_t aes_key_id)
{
  int ret_val = -1;
  uint32_t type = 0;
  uint32_t length = 0;
  uint32_t encrypted_payload_length = 0;
  const uint8_t* iv = NULL;
  const uint8_t* encrypted_payload = NULL;
  ndn_decoder_t decoder;
  decoder_init(&decoder, input, input_size);

  do {
    ret_val = decoder_get_type(&decoder, &type);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = decoder_get_length(&decoder, &length);
    if (ret_val != NDN_SUCCESS) return ret_val;
    if (type == TLV_AC_AES_IV) {
      if (length != NDN_AES_BLOCK_SIZE) return NDN_WRONG_TLV_LENGTH;
      iv = decoder.input_value + decoder.offset;
      decoder_move_forward(&decoder, length);
    }
    else if (type == TLV_AC_ENCRYPTED_PAYLOAD) {
      encrypted_payload = decoder.input_value + decoder.offset;
      encrypted_payload_length = length;
      decoder_move_forward(&decoder, length);
    }
    else {
      decoder_move_forward(&decoder, length);
    }
  }
  while (iv == NULL || encrypted_payload == NULL);

  ndn_aes_key_t* key = ndn_key_storage_get_aes_key(aes_key_id);
  if (key == NULL) {
    return NDN_AC_KEY_NOT_FOUND;
  }
  ret_val = ndn_aes_cbc_decrypt(encrypted_payload, encrypted_payload_length,
                                output, output_size, iv, key);
  if (ret_val != NDN_SUCCESS) return ret_val;
  return 0;
}