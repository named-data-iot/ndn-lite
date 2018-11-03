/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "signed_interest.h"

// this function should be invoked only after interest's signature
// info has been initialized
static uint32_t
_ndn_signed_interest_parameters_probe_value_size(const ndn_signed_interest_t* interest)
{
  uint32_t params_value_size = 0;
  if (interest->enable_Parameters)
   params_value_size += encoder_probe_block_size(TLV_Parameters, interest->parameters.size);
  // timestamp
  params_value_size += encoder_probe_block_size(TLV_SignedInterestTimestamp, 4);
  // nounce
  params_value_size += encoder_probe_block_size(TLV_Nounce, 4);
  // signature info
  params_value_size += ndn_signature_info_probe_block_size(interest->signature);
  return params_value_size;
}

// this function should be invoked only after interest's signature
// info has been initialized and signed interest parameters has been calculated
static uint32_t
_ndn_signed_interest_probe_block_size(const ndn_signed_interest_t* interest,
                                      const uint32_t signed_interest_params_value_size)
{
  uint32_t interest_buffer_size = ndn_name_probe_block_size(&interest->name);
  if (interest->enable_CanBePrefix)
    interest_buffer_size += 2;
  if (interest->enable_MustBeFresh)
    interest_buffer_size += 2;
  if (interest->enable_HopLimit)
    interest_buffer_size += 3;
  interest_buffer_size += encoder_probe_block_size(TLV_SignedInterestParameters,
                                                   signed_interest_params_value_size); // signed interest parameters
  interest_buffer_size += 6; // nounce
  interest_buffer_size += 4; // lifetime
  interest_buffer_size += ndn_signature_value_probe_block_size(&interest->signature);
  return encoder_probe_block_size(TLV_Interest, interest_buffer_size);
}

static uint32_t
_ndn_signed_interest_probe_unsigned_block()
{

}

// before signed interest encoding and signing
// uint32_t
// ndn_interest_probe_unsigned_block_size(ndn_signed_interest_t* interest, int flag)
// {
//   uint32_t tlv_total_size = 0;
//   if (flag == NDN_FLAG_WHEN_ENCODING) {
//     for (size_t i = 0; i < interest->name.components_size; i++) {
//       tlv_total_size += name_component_probe_block_size(&interest->name.components[i]);
//     }
//     return tlv_total_size;
//   }
//   if (flag == NDN_FLAG_WHEN_DECODING) {
//     for (size_t i = 0; i < interest->name.components_size - 1; i++) {
//       tlv_total_size += name_component_probe_block_size(&interest->name.components[i]);
//     }
//     return tlv_total_size;
//   }
// }

// before signed interest encoding and signing
// int
// ndn_interest_prepare_unsigned_block(ndn_encoder_t* encoder, ndn_signed_interest_t* interest, int flag)
// {
//   if (flag == NDN_FLAG_WHEN_ENCODING)
//   {
//     for (size_t i = 0; i < interest->name.components_size; i++) {
//       int result = name_component_tlv_encode(encoder, &interest->name.components[i]);
//       if (result < 0)
//         return result;
//     }
//     return 0;
//   }
//   if (flag == NDN_FLAG_WHEN_DECODING)
//   {
//     for (size_t i = 0; i < interest->name.components_size - 1; i++) {
//       int result = name_component_tlv_encode(encoder, &interest->name.components[i]);
//       if (result < 0)
//         return result;
//     }
//     return 0;
//   }

//   return -1; //error
// }


static void
_prepare_signature_info(ndn_signed_interest_t* interest, uint8_t signature_type,
                        const ndn_name_t* producer_identity, const uint8_t* key_id)
{
  ndn_signature_init(&interest->signature, signature_type);
  ndn_signature_set_key_locator(interest->signature, producer_identity);

  char key_comp_string[] = "KEY";
  name_component_from_string(&interest->signature.key_locator_name.components[interest->signature.key_locator_name.components_size],
                             key_comp_string, sizeof(key_comp_string));
  interest->signature.key_locator_name.components_size++;
  name_component_from_buffer(&interest->signature.key_locator_name.components[interest->signature.key_locator_name.components_size],
                             TLV_GenericNameComponent, key_id, 4);
  interest->signature.key_locator_name.components_size++;
}


int
ndn_signed_interest_tlv_encode_ecdsa_sign(ndn_encoder_t* encoder, ndn_signed_interest_t* interest,
                                          const ndn_name_t* producer_identity,
                                          const ndn_ecc_prv_t* prv_key)
{
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_ERROR_OVERSIZE;

  // set signature info
  _prepare_signature_info(interest, NDN_SIG_TYPE_ECDSA_SHA256, producer_identity, prv_key->key_id);

  // encode signed interest parameter block
  ndn_encoder tmp_encoder;
  uint8_t params_block[NDN_SIGNED_INTEREST_PARAMS_MAX_SIZE] = {0};
  encoder_init(&tmp_encoder, params_block, NDN_SIGNED_INTEREST_PARAMS_MAX_SIZE);
  encoder_append_type(&tmp_encoder, TLV_SignedInterestParameters);
  uint32_t params_value_size = _ndn_signed_interest_parameters_probe_value_size(interest);
  encoder_append_length(&tmp_encoder, params_value_size);
  if (interest->enable_Parameters) {
    encoder_append_type(&tmp_encoder, TLV_Parameters);
    encoder_append_length(&tmp_encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(&tmp_encoder, interest->parameters.value, interest->parameters.size);
  }
  encoder_append_type(&tmp_encoder, TLV_SignedInterestTimestamp);
  encoder_append_length(&tmp_encoder, 4);
  encoder_append_uint32_value(&tmp_encoder, interest->signature_timestamp);
  encoder_append_type(&tmp_encoder, TLV_Nounce);
  encoder_append_length(&tmp_encoder, 4);
  encoder_append_uint32_value(&tmp_encoder, interest->signature_nounce);
  ndn_block params_block = {.value = params_block,
                            .size = &tmp_encoder.offset,
                            .max_size = NDN_SIGNED_INTEREST_PARAMS_MAX_SIZE};

  // calculate digest component and append it to the name
  name_component_init(&interest->name.components[interest->interest.name.components_size],
                      TLV_ParametersSha256DigestComponent);
  ndn_signer_t signer;
  ndn_signer_init(&signer, params_block.value, params_block.size,
                  interest->name.components[interest->interest.name.components_size].value,
                  NAME_COMPONENT_BUFFER_SIZE);
  int result = ndn_signer_sha256_sign(&signer);
  if (result < 0)
    return result;
  interest->name.components_size++;

  // calculate signature

  uint32_t interest_block_size = _ndn_signed_interest_probe_block_size(interest, params_value_size);



  //================

  // signature generation
  uint8_t unsigned_block[NDN_NAME_MAX_BLOCK_SIZE];
  encoder_init(&encoder, unsigned_block, NDN_NAME_MAX_BLOCK_SIZE);
  ndn_name_tlv_encode(&encoder, interest->interest.name);

  ndn_signer_t signer;
  ndn_signer_init(&signer, encoder.output_value, encoder.offset,
                  interest->signature.sig_value, interest->signature.sig_size);
  int result = ndn_signer_ecdsa_sign(&signer, prv_key->key_value, prv_key->key_size,
                                     prv_key->curve_type);
  if (result < 0)
    return result;

  // append signature value block
  encoder_init(&encoder,
               interest->interest.name.components[interest->interest.name.components_size].value,
               NAME_COMPONENT_BLOCK_SIZE);
  ndn_signature_value_tlv_encode(&encoder, &interest->signature);
  interest->interest.name.components[interest->interest.name.components_size].size = encoder.offset;
  interest->interest.name.components_size++;
}

int
ndn_interest_hmac_sign(ndn_signed_interest_t* interest,
                       const ndn_name_t* producer_identity, const ndn_hmac_key_t* hmac_key)
{
  if (interest->interest.name.components_size + 4 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_ERROR_OVERSIZE;

  // set signature info
  _prepare_timestamp_nounce(interest, NDN_SIG_TYPE_HMAC_SHA256, producer_identity, prv_key->key_id);
  uint32_t info_size = ndn_signature_info_probe_block_size(&interest->signature);

  // timestamp and nounce
  _prepare_timestamp_nounce(interest, interest.timestamp, interest.nounce);

  // append signature info component
  ndn_encoder_t encoder;
  encoder_init(&encoder, interest->interest.name.components[interest->interest.name.components_size].value,
               NAME_COMPONENT_BLOCK_SIZE);
  ndn_signature_info_tlv_encode(&encoder, &interest->signature);
  interest->interest.name.components[interest->interest.name.components_size].size = encoder.offset;
  interest->interest.name.components_size++;

  // signature generation
  uint8_t unsigned_block[NDN_NAME_MAX_BLOCK_SIZE];
  encoder_init(&encoder, unsigned_block, NDN_NAME_MAX_BLOCK_SIZE);
  ndn_name_tlv_encode(&encoder, interest->interest.name);

  ndn_signer_t signer;
  ndn_signer_init(&signer, encoder.output_value, encoder.offset,
                  interest->signature.sig_value, interest->signature.sig_size);
  int result = ndn_signer_hmac_sign(&signer, prv_key->key_value, prv_key->key_size,
                                    prv_key->curve_type);
  if (result < 0)
    return result;

  // append signature value block
  encoder_init(&encoder,
               interest->interest.name.components[interest->interest.name.components_size].value,
               NAME_COMPONENT_BLOCK_SIZE);
  ndn_signature_value_tlv_encode(&encoder, &interest->signature);
  interest->interest.name.components[interest->interest.name.components_size].size = encoder.offset;
  interest->interest.name.components_size++;
}

int
ndn_signed_interest_digest_sign(ndn_signed_interest_t* interest)
{
  if (interest->interest.name.components_size + 4 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_ERROR_OVERSIZE;

  // set signature info
  _prepare_timestamp_nounce(interest, NDN_SIG_TYPE_HMAC_SHA256, producer_identity, prv_key->key_id);
  uint32_t info_size = ndn_signature_info_probe_block_size(&interest->signature);

  // timestamp and nounce
  _prepare_timestamp_nounce(interest, interest.timestamp, interest.nounce);

  // append signature info component
  ndn_encoder_t encoder;
  encoder_init(&encoder, interest->interest.name.components[interest->interest.name.components_size].value,
               NAME_COMPONENT_BLOCK_SIZE);
  ndn_signature_info_tlv_encode(&encoder, &interest->signature);
  interest->interest.name.components[interest->interest.name.components_size].size = encoder.offset;
  interest->interest.name.components_size++;

  // signature generation
  uint8_t unsigned_block[NDN_NAME_MAX_BLOCK_SIZE];
  encoder_init(&encoder, unsigned_block, NDN_NAME_MAX_BLOCK_SIZE);
  ndn_name_tlv_encode(&encoder, interest->interest.name);

  ndn_signer_t signer;
  ndn_signer_init(&signer, encoder.output_value, encoder.offset,
                  interest->signature.sig_value, interest->signature.sig_size);
  int result = ndn_signer_sha256_sign(&signer);
  if (result < 0)
    return result;

  // append signature value block
  encoder_init(&encoder,
               interest->interest.name.components[interest->interest.name.components_size].value,
               NAME_COMPONENT_BLOCK_SIZE);
  ndn_signature_value_tlv_encode(&encoder, &interest->signature);
  interest->interest.name.components[interest->interest.name.components_size].size = encoder.offset;
  interest->interest.name.components_size++;
}

int
ndn_interest_ecdsa_verify(ndn_interest_t* interest, const ndn_ecc_pub_t* pub_key)
{


  // decode signature info
  ndn_decoder_t decoder;
  ndn_signature_t signature;
  uint32_t info_size = interest->name.components[interest->name.components_size - 2].size;
  uint8_t buffer_info[info_size];
  decoder_init(&decoder, interest->name.components[interest->name.components_size - 2].value,
               interest->name.components[interest->name.components_size - 2].size);
  ndn_signature_info_tlv_decode(&decoder, &signature);

  // decode signature value
  name_component_t sig_value_component = interest->name.components[interest->name.components_size - 1];
  decoder_init(&temp_decoder, interest->name.components[interest->name.components_size - 1].value,
               interest->name.components[interest->name.components_size - 1].size);
  ndn_signature_value_tlv_decode(&temp_decoder, &signature);


  ndn_encoder_t encoder;
  uint8_t unsigned_block[NDN_NAME_MAX_BLOCK_SIZE];
  encoder_init(&encoder, unsigned_block, NDN_NAME_MAX_BLOCK_SIZE);


  //=========================

  encoder_init(&temp_encoder, buffer_unsigned, unsigned_size);
  ndn_interest_prepare_unsigned_block(&temp_encoder, interest, NDN_FLAG_WHEN_DECODING);
  ndn_verifier_t verifier;
  ndn_verifier_init(&verifier, temp_encoder.output_value,
                    temp_encoder.offset,
                    interest->signature.sig_value, interest->signature.sig_size);
  int result = ndn_verifier_ecdsa_verify(&verifier, pub_key->key_value,
                                         pub_key->key_size, pub_key->curve_type);
  if (result)
    return result;

  return 0;
}

int
ndn_interest_tlv_decode_hmac_verify(ndn_signed_interest_t* interest, const uint8_t* block_value, uint32_t block_size,
                                    const ndn_hmac_key_t* hmac_key)
{
  ndn_decoder_t decoder;
  ndn_decoder_t temp_decoder;
  ndn_encoder_t temp_encoder;

  decoder_init(&decoder, block_value, block_size);
  ndn_interest_from_block(interest, block_value, block_size);

  uint32_t info_size = interest->name.components[interest->name.components_size - 2].size;
  uint8_t buffer_info[info_size];
  decoder_init(&temp_decoder, buffer_info, info_size);
  // signature info
  ndn_signature_info_tlv_decode(&temp_decoder, &interest->signature);

  uint32_t unsigned_size = ndn_interest_probe_unsigned_block_size(interest, NDN_FLAG_WHEN_DECODING);
  uint8_t buffer_unsigned[unsigned_size];
  encoder_init(&temp_encoder, buffer_unsigned, unsigned_size);
  ndn_interest_prepare_unsigned_block(&temp_encoder, interest, NDN_FLAG_WHEN_DECODING);

  name_component_t sig_value_component = interest->name.components[interest->name.components_size - 1];
  decoder_init(&temp_decoder, sig_value_component.value, sig_value_component.size);
  // signature value
  ndn_signature_value_tlv_decode(&temp_decoder, &interest->signature);

  ndn_verifier_t verifier;
  ndn_verifier_init(&verifier, temp_encoder.output_value,
                    temp_encoder.offset,
                    interest->signature.sig_value, interest->signature.sig_size);
  int result = ndn_verifier_hmac_verify(&verifier, hmac_key->key_value, hmac_key->key_size);
  if (result)
    return result;

  return 0;
}

int
ndn_interest_tlv_decode_digest_verify(ndn_signed_interest_t* interest, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  ndn_decoder_t temp_decoder;
  ndn_encoder_t temp_encoder;

  decoder_init(&decoder, block_value, block_size);
  ndn_interest_from_block(interest, block_value, block_size);

  uint32_t info_size = interest->name.components[interest->name.components_size - 2].size;
  uint8_t buffer_info[info_size];
  decoder_init(&temp_decoder, buffer_info, info_size);
  // signature info
  ndn_signature_info_tlv_decode(&temp_decoder, &interest->signature);

  uint32_t unsigned_size = ndn_interest_probe_unsigned_block_size(interest, NDN_FLAG_WHEN_DECODING);
  uint8_t buffer_unsigned[unsigned_size];
  encoder_init(&temp_encoder, buffer_unsigned, unsigned_size);
  ndn_interest_prepare_unsigned_block(&temp_encoder, interest, NDN_FLAG_WHEN_DECODING);

  name_component_t sig_value_component = interest->name.components[interest->name.components_size - 1];
  decoder_init(&temp_decoder, sig_value_component.value, sig_value_component.size);
  // signature value
  ndn_signature_value_tlv_decode(&temp_decoder, &interest->signature);

  ndn_verifier_t verifier;
  ndn_verifier_init(&verifier, temp_encoder.output_value,
                    temp_encoder.offset,
                    interest->signature.sig_value, interest->signature.sig_size);
  int result = ndn_verifier_sha256_verify(&verifier);
  if (result)
    return result;

  return 0;
}
