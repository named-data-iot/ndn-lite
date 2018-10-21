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

// int
// ndn_signature_tlv_decode(ndn_signature_t* signature, ndn_decoder_t* decoder)
// {
//   uint32_t probe;

//   signature->enable_keylocator = 0;
//   signature->enable_keydigest = 0;

//   // signatureinfo header
//   decoder_get_type(decoder, &probe);
//   decoder_get_length(decoder, &probe);

//   // signature type tlv
//   decoder_get_type(decoder, &probe);
//   decoder_get_length(decoder, &probe);
//   decoder_get_type(decoder, &signature->type);

//   //initialize keylocator
//   switch(signature->type){
//   case NDN_SIG_TYPE_DIGEST_SHA256:
//     signature->signature_value.size = 32;
//     break;

//   case NDN_SIG_TYPE_ECDSA_SHA256:
//     signature->signature_value.size = 64;
//     break;

//   case NDN_SIG_TYPE_HMAC_SHA256:
//     signature->signature_value.size = 32;
//     break;

//   case NDN_SIG_TYPE_RSA_SHA256:
//     signature->signature_value.size = 128;
//     break;
//   }

//   // check keylocator block
//   decoder_get_type(decoder, &probe);
//   if(probe == TLV_KeyLocator){
//     signature->enable_keylocator = 1;
//     decoder_get_length(decoder, &probe);
//     size_t keyname_length = probe;

//     // keyname or keydigest
//     decoder_get_type(decoder, &probe);
//     if(probe == TLV_KeyLocatorDigest){
//       signature->enable_keydigest = 1;
//       decoder_get_length(decoder, &probe);
//       signature->keylocator.keydigest.size = probe;
//       signature->keylocator.keydigest.value = signature->keylocator_holder;
//       decoder_get_raw_buffer_value(decoder, signature->keylocator.keydigest.value,
//                                    signature->keylocator.keydigest.size);
//     }
//     else{
//       signature->enable_keydigest = 0;
//       decoder_move_backward(decoder, 1);
//       ndn_name_tlv_decode(&signature->keylocator.keyname, decoder);
//     }
//   }
//   else decoder_move_backward(&decoder, 1);

//   // signaturevalue
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   signature->signature_value.value = signature->value_holder;
//   decoder_get_raw_buffer_value(&decoder, signature->signature_value.value,
//                                signature->signature_value.size);

//   return 0;
// }
