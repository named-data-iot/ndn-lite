/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "interest.h"
#include "../security/sign-verify.h"

int
ndn_interest_from_block(ndn_interest_t* interest, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  uint32_t type = 0;
  decoder_get_type(&decoder, &type);
  if (type != TLV_Interest) {
    return NDN_ERROR_WRONG_TLV_TYPE;
  }
  uint32_t interest_buffer_length = 0;
  decoder_get_length(&decoder, &interest_buffer_length);

  // name
  int result = ndn_name_tlv_decode(&decoder, &interest->name);
  if (result < 0) {
    return result;
  }
  while (decoder.offset < block_size) {
    decoder_get_type(&decoder, &type);
    uint32_t length = 0;
    if (type == TLV_CanBePrefix) {
      interest->enable_CanBePrefix = 1;
      decoder_get_length(&decoder, &length);
    }
    else if (type == TLV_MustBeFresh) {
      interest->enable_MustBeFresh = 1;
      decoder_get_length(&decoder, &length);
    }
    else if (type == TLV_Nounce) {
      decoder_get_length(&decoder, &length);
      decoder_get_raw_buffer_value(&decoder, interest->nounce, length);
    }
    else if (type == TLV_InterestLifetime) {
      decoder_get_length(&decoder, &length);
      decoder_get_raw_buffer_value(&decoder, interest->lifetime, length);
    }
    else if (type == TLV_HopLimit) {
      interest->enable_HopLimit = 1;
      decoder_get_length(&decoder, &length);
      decoder_get_byte_value(&decoder, &interest->hop_limit);
    }
    else if (type == TLV_Parameters) {
      interest->enable_Parameters = 1;
      decoder_get_length(&decoder, &interest->parameters.size);
      decoder_get_raw_buffer_value(&decoder, interest->parameters.value,
                                   interest->parameters.size);
    }
    else
      return NDN_ERROR_WRONG_TLV_TYPE;
  }
  return 0;
}

int
ndn_interest_tlv_encode(ndn_encoder_t* encoder, const ndn_interest_t* interest)
{
  encoder_append_type(encoder, TLV_Interest);

  uint32_t interest_block_size = ndn_interest_probe_block_size(interest);

  encoder_append_length(encoder, interest_block_size);
  ndn_name_tlv_encode(encoder, &interest->name);

  if (interest->enable_CanBePrefix) {
    encoder_append_type(encoder, TLV_CanBePrefix);
    encoder_append_length(encoder, 0);
  }
  if (interest->enable_MustBeFresh) {
    encoder_append_type(encoder, TLV_MustBeFresh);
    encoder_append_length(encoder, 0);
  }
  // nounce
  encoder_append_type(encoder, TLV_Nounce);
  encoder_append_length(encoder, 4);
  encoder_append_raw_buffer_value(encoder, interest->nounce, 4);
  // lifetime
  encoder_append_type(encoder, TLV_InterestLifetime);
  encoder_append_length(encoder, 2);
  encoder_append_raw_buffer_value(encoder, interest->lifetime, 2);
  if (interest->enable_HopLimit) {
    encoder_append_type(encoder, TLV_HopLimit);
    encoder_append_length(encoder, 1);
    encoder_append_byte_value(encoder, interest->hop_limit);
  }
  if (interest->enable_Parameters) {
    encoder_append_type(encoder, TLV_Parameters);
    encoder_append_length(encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(encoder, interest->parameters.value, interest->parameters.size);
  }
  return 0;
}

int
ndn_interest_prepare_unsigned_block(ndn_encoder_t* encoder, ndn_interest_t* interest)
{
  // prepare unsigned name
  int block_sizes[interest->name.components_size];
  size_t value_size = 0;
  for (size_t i = 0; i < interest->name.components_size; i++) {
    block_sizes[i] = name_component_probe_block_size(&interest->name.components[i]);
    value_size += block_sizes[i];
  }
  for (size_t i = 0; i < interest->name.components_size; i++) {
    int result = name_component_tlv_encode(encoder, &interest->name.components[i]);
    if (result < 0)
      return result;
  }
  return 0;
}

int
ndn_interest_tlv_encode_digest_sign(ndn_encoder_t* encoder, ndn_interest_t* interest)
{
  ndn_encoder_t in_interest_encoder;

  // set signature info
  ndn_signature_init(&interest->signature, NDN_SIG_TYPE_DIGEST_SHA256);
  uint32_t info_size = ndn_signature_info_probe_block_size(&interest->signature);

  // timestamp and nounce
  name_component_t signature_timestamp;
  name_component_from_buffer(&signature_timestamp, TLV_GenericNameComponent,
                            interest->Signature_timestamp, 15);
  ndn_name_append_component(&interest->name, &signature_timestamp);

  name_component_t signature_nounce;
  name_component_from_buffer(&signature_nounce, TLV_GenericNameComponent,
                            interest->Signature_nounce, 4);
  ndn_name_append_component(&interest->name, &signature_nounce);

  // signature info  
  name_component_t signature_info;
  uint8_t buffer_info[info_size];
  encoder_init(&in_interest_encoder, buffer_info, info_size);
  ndn_signature_info_tlv_encode(&in_interest_encoder, &interest->signature);
  name_component_from_buffer(&signature_info, TLV_GenericNameComponent,
                             in_interest_encoder.output_value, in_interest_encoder.offset);
  ndn_name_append_component(&interest->name, &signature_info);

  // signature value
  name_component_t signature_value;
  uint32_t name_size = ndn_name_probe_block_size(&interest->name);
  uint8_t buffer_unsigned[name_size];
  encoder_init(&in_interest_encoder, buffer_unsigned, name_size);
  uint32_t sign_input_starting = in_interest_encoder.offset;   
  ndn_interest_prepare_unsigned_block(&in_interest_encoder, &interest);
  uint32_t sign_input_ending = encoder->offset;
  
  ndn_signer_t signer;
  ndn_signer_init(&signer, sign_input_starting,
                  sign_input_ending - sign_input_starting,
                  interest->signature.sig_value, interest->signature.sig_size);               
  int result = ndn_signer_sha256_sign(&signer);
  if (result < 0)
    return result;

  uint32_t value_size = ndn_signature_value_probe_block_size(&interest->signature);
  uint8_t buffer_value[value_size];
  encoder_init(&in_interest_encoder, buffer_value, value_size);
  ndn_signature_value_tlv_encode(&in_interest_encoder, &interest->signature);
  name_component_from_buffer(&signature_info, TLV_GenericNameComponent,
                             in_interest_encoder.output_value, in_interest_encoder.offset);
  ndn_name_append_component(&interest->name, &signature_value);

  // ordinary interst tlv encoding
  return ndn_interest_tlv_encode(encoder, interest);
}

int
ndn_interest_tlv_encode_ecdsa_sign(ndn_encoder_t* encoder, ndn_interest_t* interest,
                               const ndn_name_t* producer_identity, const ndn_ecc_prv_t* prv_key)
{
  ndn_encoder_t in_interest_encoder;

  // set signature info
  ndn_signature_init(&interest->signature, NDN_SIG_TYPE_ECDSA_SHA256);

  interest->signature.enable_KeyLocator = 1;
  interest->signature.key_locator_name = *producer_identity;
  name_component_t key_component;
  char key_comp_string[] = "KEY";
  name_component_from_string(&key_component, key_comp_string, sizeof(key_comp_string));
  name_component_t key_id_component;
  name_component_from_buffer(&key_id_component, TLV_GenericNameComponent, prv_key->key_id, 4);
  ndn_name_append_component(&interest->signature.key_locator_name, &key_component);
  ndn_name_append_component(&interest->signature.key_locator_name, &key_id_component);

  uint32_t info_size = ndn_signature_info_probe_block_size(&interest->signature);

  // timestamp and nounce
  name_component_t signature_timestamp;
  name_component_from_buffer(&signature_timestamp, TLV_GenericNameComponent,
                            interest->Signature_timestamp, 15);
  ndn_name_append_component(&interest->name, &signature_timestamp);

  name_component_t signature_nounce;
  name_component_from_buffer(&signature_nounce, TLV_GenericNameComponent,
                            interest->Signature_nounce, 4);
  ndn_name_append_component(&interest->name, &signature_nounce);

  // signature info  
  name_component_t signature_info;
  uint8_t buffer_info[info_size];
  encoder_init(&in_interest_encoder, buffer_info, info_size);
  ndn_signature_info_tlv_encode(&in_interest_encoder, &interest->signature);
  name_component_from_buffer(&signature_info, TLV_GenericNameComponent,
                             in_interest_encoder.output_value, in_interest_encoder.offset);
  ndn_name_append_component(&interest->name, &signature_info);

  // signature value
  name_component_t signature_value;
  uint32_t name_size = ndn_name_probe_block_size(&interest->name);
  uint8_t buffer_unsigned[name_size];
  encoder_init(&in_interest_encoder, buffer_unsigned, name_size);
  uint32_t sign_input_starting = in_interest_encoder.offset;   
  ndn_interest_prepare_unsigned_block(&in_interest_encoder, &interest);
  uint32_t sign_input_ending = encoder->offset;
  
  ndn_signer_t signer;
  ndn_signer_init(&signer, sign_input_starting,
                  sign_input_ending - sign_input_starting,
                  interest->signature.sig_value, interest->signature.sig_size);               
  int result = ndn_signer_ecdsa_sign(&signer, prv_key->key_value,
                                     prv_key->key_size, prv_key->curve_type);
  if (result < 0)
    return result;

  uint32_t value_size = ndn_signature_value_probe_block_size(&interest->signature);
  uint8_t buffer_value[value_size];
  encoder_init(&in_interest_encoder, buffer_value, value_size);
  ndn_signature_value_tlv_encode(&in_interest_encoder, &interest->signature);
  name_component_from_buffer(&signature_info, TLV_GenericNameComponent,
                             in_interest_encoder.output_value, in_interest_encoder.offset);
  ndn_name_append_component(&interest->name, &signature_value);

  // ordinary interst tlv encoding
  return ndn_interest_tlv_encode(encoder, interest);
}

int
ndn_data_tlv_encode_hmac_sign(ndn_encoder_t* encoder, ndn_data_t* data,
                              const ndn_name_t* producer_identity, const ndn_hmac_key_t* hmac_key)
{
  ndn_encoder_t in_interest_encoder;
  
  // set signature info
  ndn_signature_init(&data->signature, NDN_SIG_TYPE_HMAC_SHA256);

  data->signature.enable_KeyLocator = 1;
  data->signature.key_locator_name = *producer_identity;
  name_component_t key_component;
  char key_comp_string[] = "KEY";
  name_component_from_string(&key_component, key_comp_string, sizeof(key_comp_string));
  name_component_t key_id_component;
  name_component_from_buffer(&key_id_component, TLV_GenericNameComponent, hmac_key->key_id, 4);
  ndn_name_append_component(&data->signature.key_locator_name, &key_component);
  ndn_name_append_component(&data->signature.key_locator_name, &key_id_component);

  uint32_t info_size = ndn_signature_info_probe_block_size(&interest->signature);

  // timestamp and nounce
  name_component_t signature_timestamp;
  name_component_from_buffer(&signature_timestamp, TLV_GenericNameComponent,
                            interest->Signature_timestamp, 15);
  ndn_name_append_component(&interest->name, &signature_timestamp);

  name_component_t signature_nounce;
  name_component_from_buffer(&signature_nounce, TLV_GenericNameComponent,
                            interest->Signature_nounce, 4);
  ndn_name_append_component(&interest->name, &signature_nounce);

  // signature info  
  name_component_t signature_info;
  uint8_t buffer_info[info_size];
  encoder_init(&in_interest_encoder, buffer_info, info_size);
  ndn_signature_info_tlv_encode(&in_interest_encoder, &interest->signature);
  name_component_from_buffer(&signature_info, TLV_GenericNameComponent,
                             in_interest_encoder.output_value, in_interest_encoder.offset);
  ndn_name_append_component(&interest->name, &signature_info);

  // signature value
  name_component_t signature_value;
  uint32_t name_size = ndn_name_probe_block_size(&interest->name);
  uint8_t buffer_unsigned[name_size];
  encoder_init(&in_interest_encoder, buffer_unsigned, name_size);
  uint32_t sign_input_starting = in_interest_encoder.offset;   
  ndn_interest_prepare_unsigned_block(&in_interest_encoder, &interest);
  uint32_t sign_input_ending = encoder->offset;
  
  ndn_signer_t signer;
  ndn_signer_init(&signer, sign_input_starting,
                  sign_input_ending - sign_input_starting,
                  interest->signature.sig_value, interest->signature.sig_size);               
  int result = ndn_signer_hmac_sign(&signer, hmac_key->key_value, hmac_key->key_size);
  if (result < 0)
    return result;

  uint32_t value_size = ndn_signature_value_probe_block_size(&interest->signature);
  uint8_t buffer_value[value_size];
  encoder_init(&in_interest_encoder, buffer_value, value_size);
  ndn_signature_value_tlv_encode(&in_interest_encoder, &interest->signature);
  name_component_from_buffer(&signature_info, TLV_GenericNameComponent,
                             in_interest_encoder.output_value, in_interest_encoder.offset);
  ndn_name_append_component(&interest->name, &signature_value);

  // ordinary interst tlv encoding
  return ndn_interest_tlv_encode(encoder, interest);
}

// TODO: ndn_interest_tlv_deocde_no_verify?

int
ndn_interest_tlv_decode_digest_verify(ndn_interest_t* interest, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  ndn_decoder_t in_interest_decoder;
  decoder_init(&decoder, block_value, block_size);

  uint32_t probe;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint32_t input_starting = decoder.offset;

  decoder_get_type(&decoder, &probe);
  uint32_t var = decoder_get_length(&decoder, &probe);
  uint32_t input_starting = decoder.offset;
  decoder_move_backward(&decoder, var + 1);

  // name decode
  ndn_name_tlv_decode(&decoder, &interest->name);

  uint32_t buffer_info_size = interest->name.components[interest->name.components_size - 1].size;
  uint8_t buffer_info[buffer_info_size];
  decoder_init(&in_interest_decoder, buffer_info, buffer_info_size);
  // signature info
  ndn_signature_info_tlv_decode(&in_interest_decoder, &interest->signature);
  uint32_t input_ending = decoder.offset;

  name_component_t* value_ptr = &interest->name.components[interest->name.components_size - 2];
  uint32_t name_block_size = ndn_name_probe_block_size(&interest->name);
  uint32_t value_block_size = name_component_probe_block_size(value_ptr);
  uint32_t input_ending = input_starting + name_block_size - value_block_size - var - 1;

  uint32_t buffer_value_size = value_ptr->size;
  uint8_t buffer_value[buffer_value_size];
  decoder_init(&in_interest_decoder, buffer_value, buffer_value_size);
  // signature value
  ndn_signature_value_tlv_decode(&in_interest_decoder, &interest->signature);

  ndn_verifier_t verifier;
  ndn_verifier_init(&verifier, decoder.input_value + input_starting,
                    input_ending - input_starting,
                    interest->signature.sig_value, interest->signature.sig_size);
  int result = ndn_verifier_sha256_verify(&verifier);
  if (result)
    return result;
  else
    {
      uint32_t type = 0;
      while (decoder.offset < block_size) {
        decoder_get_type(&decoder, &type);
        uint32_t length = 0;
        if (type == TLV_CanBePrefix) {
          interest->enable_CanBePrefix = 1;
          decoder_get_length(&decoder, &length);
        }
        else if (type == TLV_MustBeFresh) {
          interest->enable_MustBeFresh = 1;
          decoder_get_length(&decoder, &length);
        }
        else if (type == TLV_Nounce) {
          decoder_get_length(&decoder, &length);
          decoder_get_raw_buffer_value(&decoder, interest->nounce, length);
        }
        else if (type == TLV_InterestLifetime) {
          decoder_get_length(&decoder, &length);
          decoder_get_raw_buffer_value(&decoder, interest->lifetime, length);
        }
        else if (type == TLV_HopLimit) {
          interest->enable_HopLimit = 1;
          decoder_get_length(&decoder, &length);
          decoder_get_byte_value(&decoder, &interest->hop_limit);
        }
        else if (type == TLV_Parameters) {
          interest->enable_Parameters = 1;
          decoder_get_length(&decoder, &interest->parameters.size);
          decoder_get_raw_buffer_value(&decoder, interest->parameters.value,
                                      interest->parameters.size);
        }
        else
          return NDN_ERROR_WRONG_TLV_TYPE;
    }
    return 0;
  }
}

int
ndn_interest_tlv_decode_ecdsa_verify(ndn_interest_t* data, const uint8_t* block_value, uint32_t block_size,
                                     const ndn_ecc_pub_t* pub_key)
{
  ndn_decoder_t decoder;
  ndn_decoder_t in_interest_decoder;
  decoder_init(&decoder, block_value, block_size);

  uint32_t probe;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint32_t input_starting = decoder.offset;

  decoder_get_type(&decoder, &probe);
  uint32_t var = decoder_get_length(&decoder, &probe);
  uint32_t input_starting = decoder.offset;
  decoder_move_backward(&decoder, var + 1);

  // name decode
  ndn_name_tlv_decode(&decoder, &interest->name);

  uint32_t buffer_info_size = interest->name.components[interest->name.components_size - 1].size;
  uint8_t buffer_info[buffer_info_size];
  decoder_init(&in_interest_decoder, buffer_info, buffer_info_size);
  // signature info
  ndn_signature_info_tlv_decode(&in_interest_decoder, &interest->signature);
  uint32_t input_ending = decoder.offset;

  name_component_t* value_ptr = &interest->name.components[interest->name.components_size - 2];
  uint32_t name_block_size = ndn_name_probe_block_size(&interest->name);
  uint32_t value_block_size = name_component_probe_block_size(value_ptr);
  uint32_t input_ending = input_starting + name_block_size - value_block_size - var - 1;

  uint32_t buffer_value_size = value_ptr->size;
  uint8_t buffer_value[buffer_value_size];
  decoder_init(&in_interest_decoder, buffer_value, buffer_value_size);
  // signature value
  ndn_signature_value_tlv_decode(&in_interest_decoder, &interest->signature);

  ndn_verifier_t verifier;
  ndn_verifier_init(&verifier, decoder.input_value + input_starting,
                    input_ending - input_starting,
                    interest->signature.sig_value, interest->signature.sig_size);
  int result = ndn_verifier_ecdsa_verify(&verifier, pub_key->key_value,
                                         pub_key->key_size, pub_key->curve_type);
  if (result)
    return result;
  else
    {
      uint32_t type = 0;
      while (decoder.offset < block_size) {
        decoder_get_type(&decoder, &type);
        uint32_t length = 0;
        if (type == TLV_CanBePrefix) {
          interest->enable_CanBePrefix = 1;
          decoder_get_length(&decoder, &length);
        }
        else if (type == TLV_MustBeFresh) {
          interest->enable_MustBeFresh = 1;
          decoder_get_length(&decoder, &length);
        }
        else if (type == TLV_Nounce) {
          decoder_get_length(&decoder, &length);
          decoder_get_raw_buffer_value(&decoder, interest->nounce, length);
        }
        else if (type == TLV_InterestLifetime) {
          decoder_get_length(&decoder, &length);
          decoder_get_raw_buffer_value(&decoder, interest->lifetime, length);
        }
        else if (type == TLV_HopLimit) {
          interest->enable_HopLimit = 1;
          decoder_get_length(&decoder, &length);
          decoder_get_byte_value(&decoder, &interest->hop_limit);
        }
        else if (type == TLV_Parameters) {
          interest->enable_Parameters = 1;
          decoder_get_length(&decoder, &interest->parameters.size);
          decoder_get_raw_buffer_value(&decoder, interest->parameters.value,
                                      interest->parameters.size);
        }
        else
          return NDN_ERROR_WRONG_TLV_TYPE;
    }
    return 0;
  }
}

int
ndn_interest_tlv_decode_hmac_verify(ndn_interest_t* data, const uint8_t* block_value, uint32_t block_size,
                                    const ndn_hmac_key_t* hmac_key)
{
  ndn_decoder_t decoder;
  ndn_decoder_t in_interest_decoder;
  decoder_init(&decoder, block_value, block_size);

  uint32_t probe;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint32_t input_starting = decoder.offset;

  decoder_get_type(&decoder, &probe);
  uint32_t var = decoder_get_length(&decoder, &probe);
  uint32_t input_starting = decoder.offset;
  decoder_move_backward(&decoder, var + 1);

  // name decode
  ndn_name_tlv_decode(&decoder, &interest->name);

  uint32_t buffer_info_size = interest->name.components[interest->name.components_size - 1].size;
  uint8_t buffer_info[buffer_info_size];
  decoder_init(&in_interest_decoder, buffer_info, buffer_info_size);
  // signature info
  ndn_signature_info_tlv_decode(&in_interest_decoder, &interest->signature);
  uint32_t input_ending = decoder.offset;

  name_component_t* value_ptr = &interest->name.components[interest->name.components_size - 2];
  uint32_t name_block_size = ndn_name_probe_block_size(&interest->name);
  uint32_t value_block_size = name_component_probe_block_size(value_ptr);
  uint32_t input_ending = input_starting + name_block_size - value_block_size - var - 1;

  uint32_t buffer_value_size = value_ptr->size;
  uint8_t buffer_value[buffer_value_size];
  decoder_init(&in_interest_decoder, buffer_value, buffer_value_size);
  // signature value
  ndn_signature_value_tlv_decode(&in_interest_decoder, &interest->signature);

  ndn_verifier_t verifier;
  ndn_verifier_init(&verifier, decoder.input_value + input_starting,
                    input_ending - input_starting,
                    interest->signature.sig_value, interest->signature.sig_size);
  int result = ndn_verifier_hmac_verify(&verifier, hmac_key->key_value, hmac_key->key_size);
  if (result)
    return result;
  else
    {
      uint32_t type = 0;
      while (decoder.offset < block_size) {
        decoder_get_type(&decoder, &type);
        uint32_t length = 0;
        if (type == TLV_CanBePrefix) {
          interest->enable_CanBePrefix = 1;
          decoder_get_length(&decoder, &length);
        }
        else if (type == TLV_MustBeFresh) {
          interest->enable_MustBeFresh = 1;
          decoder_get_length(&decoder, &length);
        }
        else if (type == TLV_Nounce) {
          decoder_get_length(&decoder, &length);
          decoder_get_raw_buffer_value(&decoder, interest->nounce, length);
        }
        else if (type == TLV_InterestLifetime) {
          decoder_get_length(&decoder, &length);
          decoder_get_raw_buffer_value(&decoder, interest->lifetime, length);
        }
        else if (type == TLV_HopLimit) {
          interest->enable_HopLimit = 1;
          decoder_get_length(&decoder, &length);
          decoder_get_byte_value(&decoder, &interest->hop_limit);
        }
        else if (type == TLV_Parameters) {
          interest->enable_Parameters = 1;
          decoder_get_length(&decoder, &interest->parameters.size);
          decoder_get_raw_buffer_value(&decoder, interest->parameters.value,
                                      interest->parameters.size);
        }
        else
          return NDN_ERROR_WRONG_TLV_TYPE;
    }
    return 0;
  }
}