#include "signature.h"
#include <stdio.h>

int
ndn_signature_info_tlv_encode(ndn_encoder_t* encoder, const ndn_signature_t* signature)
{
  uint32_t info_buffer_size = encoder_probe_block_size(TLV_SignatureType, 1);
  uint32_t key_name_block_size = 0;
  uint32_t validity_period_buffer_size = 0;

  if (signature->enable_KeyLocator) {
    key_name_block_size = ndn_name_probe_block_size(&signature->key_locator_name);
    info_buffer_size += encoder_probe_block_size(TLV_KeyLocator, key_name_block_size);
  }
  if (signature->enable_ValidityPeriod) {
    validity_period_buffer_size = encoder_probe_block_size(TLV_NotBefore, 15);
    validity_period_buffer_size += encoder_probe_block_size(TLV_NotAfter, 15);
    info_buffer_size += encoder_probe_block_size(TLV_ValidityPeriod, validity_period_buffer_size);
  }

  // signatureinfo header
  encoder_append_type(encoder, TLV_SignatureInfo);
  encoder_append_length(encoder, info_buffer_size);

  // signature type
  encoder_append_type(encoder, TLV_SignatureType);
  encoder_append_length(encoder, 1);
  encoder_append_byte_value(encoder, signature->sig_type);

  // key locator
  if (signature->enable_KeyLocator) {
    encoder_append_type(encoder, TLV_KeyLocator);
    encoder_append_length(encoder, key_name_block_size);
    ndn_name_tlv_encode(encoder, &signature->key_locator_name);
  }

  // validity period
  if (signature->enable_ValidityPeriod) {
    encoder_append_type(encoder, TLV_ValidityPeriod);
    encoder_append_length(encoder, validity_period_buffer_size);

    encoder_append_type(encoder, TLV_NotBefore);
    encoder_append_length(encoder, 15);
    encoder_append_raw_buffer_value(encoder, signature->validity_period.not_before, 15);

    encoder_append_type(encoder, TLV_NotAfter);
    encoder_append_length(encoder, 15);
    encoder_append_raw_buffer_value(encoder, signature->validity_period.not_after, 15);
  }
  return 0;
}

int
ndn_signature_value_tlv_encode(ndn_encoder_t* encoder, const ndn_signature_t* signature)
{
  encoder_append_type(encoder, TLV_SignatureValue);
  encoder_append_length(encoder, signature->sig_size);
  encoder_append_raw_buffer_value(encoder, signature->sig_value, signature->sig_size);
  return 0;
}

int
ndn_signature_info_tlv_decode(ndn_decoder_t* decoder, ndn_signature_t* signature)
{
  uint32_t probe = 0;
  decoder_get_type(decoder, &probe);
  if (probe != TLV_SignatureInfo)
    return NDN_ERROR_WRONG_TLV_TYPE;
  uint32_t value_length = 0;
  decoder_get_length(decoder, &value_length);
  uint32_t value_starting = decoder->offset;

  // signature type
  decoder_get_type(decoder, &probe);
  decoder_get_length(decoder, &probe);
  decoder_get_byte_value(decoder, &signature->sig_type);

  while (decoder->offset < value_starting + value_length) {
    decoder_get_type(decoder, &probe);
    if (probe == TLV_KeyLocator) {
      signature->enable_KeyLocator = 1;
      decoder_get_length(decoder, &probe);
      ndn_name_tlv_decode(decoder, &signature->key_locator_name);
    }
    else if (probe == TLV_ValidityPeriod) {
      signature->enable_ValidityPeriod = 1;
      decoder_get_length(decoder, &probe);

      decoder_get_type(decoder, &probe);
      decoder_get_length(decoder, &probe);
      decoder_get_raw_buffer_value(decoder, signature->validity_period.not_before, 15);

      decoder_get_type(decoder, &probe);
      decoder_get_length(decoder, &probe);
      decoder_get_raw_buffer_value(decoder, signature->validity_period.not_after, 15);
    }
    else
      return NDN_ERROR_WRONG_TLV_TYPE;
  }
  return 0;
}

int
ndn_signature_value_tlv_decode(ndn_decoder_t* decoder, ndn_signature_t* signature)
{
  uint32_t type = 0;
  decoder_get_type(decoder, &type);
  if (type != TLV_SignatureValue)
    return NDN_ERROR_WRONG_TLV_TYPE;
  decoder_get_length(decoder, &signature->sig_size);
  decoder_get_raw_buffer_value(decoder, signature->sig_value, signature->sig_size);
  return 0;
}
