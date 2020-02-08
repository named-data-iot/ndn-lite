/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "signature.h"

int
ndn_signature_info_tlv_encode(ndn_encoder_t* encoder, const ndn_signature_t* signature)
{
  int ret_val = -1;
  uint32_t info_buffer_size = encoder_probe_block_size(TLV_SignatureType, 1);
  uint32_t key_name_block_size = 0;
  uint32_t validity_period_buffer_size = 0;

  if (signature->enable_KeyLocator > 0) {
    key_name_block_size = ndn_name_probe_block_size(&signature->key_locator_name);
    info_buffer_size += encoder_probe_block_size(TLV_KeyLocator, key_name_block_size);
  }
  if (signature->enable_ValidityPeriod > 0) {
    validity_period_buffer_size = encoder_probe_block_size(TLV_NotBefore, 15);
    validity_period_buffer_size += encoder_probe_block_size(TLV_NotAfter, 15);
    info_buffer_size += encoder_probe_block_size(TLV_ValidityPeriod, validity_period_buffer_size);
  }
  if (signature->enable_SignatureNonce > 0) {
    info_buffer_size += encoder_probe_block_size(TLV_Nonce, 4);
  }
  if (signature->enable_Timestamp > 0) {
    info_buffer_size += encoder_probe_block_size(TLV_Timestamp,
                                                 encoder_probe_uint_length(signature->timestamp));
  }
  if (signature->enable_Seqnum > 0) {
    info_buffer_size += encoder_probe_block_size(TLV_SeqNum,
                                                 encoder_probe_uint_length(signature->seqnum));
  }

  // signatureinfo header
  if (signature->is_interest) {
    ret_val = encoder_append_type(encoder, TLV_InterestSignatureInfo);
  }
  else {
    ret_val = encoder_append_type(encoder, TLV_SignatureInfo);
  }
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, info_buffer_size);
  if (ret_val != NDN_SUCCESS) return ret_val;

  // signature type
  ret_val = encoder_append_type(encoder, TLV_SignatureType);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, 1);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_byte_value(encoder, signature->sig_type);
  if (ret_val != NDN_SUCCESS) return ret_val;

  // key locator
  if (signature->enable_KeyLocator) {
    ret_val = encoder_append_type(encoder, TLV_KeyLocator);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, key_name_block_size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = ndn_name_tlv_encode(encoder, &signature->key_locator_name);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }

  // signature nonce
  if (signature->enable_SignatureNonce > 0) {
    ret_val = encoder_append_type(encoder, TLV_Nonce);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, 4);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_uint32_value(encoder, signature->signature_nonce);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }

  // timestamp
  if (signature->enable_Timestamp > 0) {
    ret_val = encoder_append_type(encoder, TLV_Timestamp);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, encoder_probe_uint_length(signature->timestamp));
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_uint_value(encoder, signature->timestamp);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }

  // timestamp
  if (signature->enable_Seqnum > 0) {
    ret_val = encoder_append_type(encoder, TLV_SeqNum);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, encoder_probe_uint_length(signature->seqnum));
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_uint_value(encoder, signature->seqnum);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }

  // validity period
  if (signature->enable_ValidityPeriod) {
    ret_val = encoder_append_type(encoder, TLV_ValidityPeriod);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, validity_period_buffer_size);
    if (ret_val != NDN_SUCCESS) return ret_val;

    ret_val = encoder_append_type(encoder, TLV_NotBefore);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, 15);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(encoder, signature->validity_period.not_before, 15);
    if (ret_val != NDN_SUCCESS) return ret_val;

    ret_val = encoder_append_type(encoder, TLV_NotAfter);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(encoder, 15);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(encoder, signature->validity_period.not_after, 15);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  return 0;
}

int
ndn_signature_value_tlv_encode(ndn_encoder_t* encoder, const ndn_signature_t* signature)
{
  int ret_val = -1;
  if (signature->is_interest) {
    ret_val = encoder_append_type(encoder, TLV_InterestSignatureValue);
  }
  else {
    ret_val = encoder_append_type(encoder, TLV_SignatureValue);
  }
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, signature->sig_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_raw_buffer_value(encoder, signature->sig_value, signature->sig_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  return 0;
}

int
ndn_signature_info_tlv_decode(ndn_decoder_t* decoder, ndn_signature_t* signature)
{
  int ret_val = -1;
  ndn_signature_init(signature, false);

  uint32_t probe = 0;
  ret_val = decoder_get_type(decoder, &probe);
  if (ret_val != NDN_SUCCESS) return ret_val;
  if (probe == TLV_SignatureInfo) {
    signature->is_interest = false;
  }
  else if (probe == TLV_InterestSignatureInfo) {
    signature->is_interest = true;
  }
  else {
    return NDN_WRONG_TLV_TYPE;
  }
  uint32_t value_length = 0;
  ret_val = decoder_get_length(decoder, &value_length);
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint32_t value_starting = decoder->offset;

  // signature type
  ret_val = decoder_get_type(decoder, &probe);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = decoder_get_length(decoder, &probe);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = decoder_get_byte_value(decoder, &signature->sig_type);
  if (ret_val != NDN_SUCCESS) return ret_val;

  while (decoder->offset < value_starting + value_length) {
    ret_val = decoder_get_type(decoder, &probe);
    if (ret_val != NDN_SUCCESS) return ret_val;
    if (probe == TLV_KeyLocator) {
      signature->enable_KeyLocator = 1;
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = ndn_name_tlv_decode(decoder, &signature->key_locator_name);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (probe == TLV_ValidityPeriod) {
      signature->enable_ValidityPeriod = 1;
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;

      ret_val = decoder_get_type(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_raw_buffer_value(decoder, signature->validity_period.not_before, 15);
      if (ret_val != NDN_SUCCESS) return ret_val;

      ret_val = decoder_get_type(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_raw_buffer_value(decoder, signature->validity_period.not_after, 15);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (probe == TLV_Nonce) {
      signature->enable_SignatureNonce = 1;
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      if (probe != 4) {
        return NDN_WRONG_TLV_LENGTH;
      }
      ret_val = decoder_get_uint32_value(decoder, &signature->signature_nonce);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (probe == TLV_Timestamp) {
      signature->enable_Timestamp = 1;
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_uint_value(decoder, probe, &signature->timestamp);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else if (probe == TLV_SeqNum) {
      signature->enable_Seqnum = 1;
      ret_val = decoder_get_length(decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      ret_val = decoder_get_uint_value(decoder, probe, &signature->seqnum);
      if (ret_val != NDN_SUCCESS) return ret_val;
    }
    else
      return NDN_WRONG_TLV_TYPE;
  }
  return 0;
}

int
ndn_signature_value_tlv_decode(ndn_decoder_t* decoder, ndn_signature_t* signature)
{
  int ret_val = -1;
  uint32_t probe = 0;
  ret_val = decoder_get_type(decoder, &probe);
  if (ret_val != NDN_SUCCESS) return ret_val;
  if (probe == TLV_SignatureValue) {
    signature->is_interest = false;
  }
  else if (probe == TLV_InterestSignatureValue) {
    signature->is_interest = true;
  }
  else {
    return NDN_WRONG_TLV_TYPE;
  }
  ret_val = decoder_get_length(decoder, &probe);
  if (probe > NDN_SEC_MAX_SIG_SIZE)
    return NDN_WRONG_TLV_LENGTH;
  if (probe < NDN_SEC_MIN_SIG_SIZE)
    return NDN_WRONG_TLV_LENGTH;
  signature->sig_size = probe;
  ret_val = decoder_get_raw_buffer_value(decoder, signature->sig_value, signature->sig_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  return 0;
}
