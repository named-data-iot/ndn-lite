/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "signed-interest.h"
#include "../security/sign-verify.h"

/************************************************************/
/*  Helper functions for signed interest APIs               */
/*  Not supposed to be used by library users                */
/************************************************************/

// this function should be invoked only after interest's signature
// info has been initialized
static uint32_t
_ndn_signed_interest_parameters_probe_value_size(const ndn_interest_t* interest)
{
  uint32_t params_value_size = 0;
  if (interest->enable_Parameters)
   params_value_size += encoder_probe_block_size(TLV_Parameters, interest->parameters.size);
  // timestamp
  params_value_size += encoder_probe_block_size(TLV_SignedInterestTimestamp, 4);
  // nounce
  params_value_size += encoder_probe_block_size(TLV_Nounce, 4);
  // signature info
  params_value_size += ndn_signature_info_probe_block_size(&interest->signature);
  return params_value_size;
}

// this function should be invoked only after interest's signature
// info has been initialized and signed interest parameters has been calculated
static uint32_t
_ndn_signed_interest_probe_block_size(const ndn_interest_t* interest,
                                      const uint32_t signed_interest_params_value_size)
{
  uint32_t interest_buffer_size = ndn_name_probe_block_size(&interest->name);
  if (interest->enable_CanBePrefix)
    interest_buffer_size += 2;
  if (interest->enable_MustBeFresh)
    interest_buffer_size += 2;
  if (interest->enable_HopLimit)
    interest_buffer_size += 3;
  // signed interest parameters
  interest_buffer_size += encoder_probe_block_size(TLV_SignedInterestParameters,
                                                   signed_interest_params_value_size);
  interest_buffer_size += 6; // nounce
  interest_buffer_size += 4; // lifetime
  interest_buffer_size += ndn_signature_value_probe_block_size(&interest->signature);
  return encoder_probe_block_size(TLV_Interest, interest_buffer_size);
}

static void
_prepare_signature_info(ndn_interest_t* interest, uint8_t signature_type,
                        const ndn_name_t* producer_identity, uint32_t key_id)
{
  uint8_t raw_key_id[4] = {0};
  raw_key_id[0] = (key_id >> 24) & 0xFF;
  raw_key_id[1] = (key_id >> 16) & 0xFF;
  raw_key_id[2] = (key_id >> 8) & 0xFF;
  raw_key_id[3] = key_id & 0xFF;

  ndn_signature_init(&interest->signature, signature_type);
  ndn_signature_set_key_locator(&interest->signature, producer_identity);

  // append /KEY and /<KEY-ID> in key locator name
  char key_comp_string[] = "KEY";
  int pos = interest->signature.key_locator_name.components_size;
  name_component_from_string(&interest->signature.key_locator_name.components[pos],
                             key_comp_string, sizeof(key_comp_string));
  interest->signature.key_locator_name.components_size++;
  pos = interest->signature.key_locator_name.components_size;
  name_component_from_buffer(&interest->signature.key_locator_name.components[pos],
                             TLV_GenericNameComponent, raw_key_id, 4);
  interest->signature.key_locator_name.components_size++;
}

// this function should be invoked only after interest's signature
// info has been initialized
static void
_prepare_signed_interest_parameters_block(ndn_interest_t* interest,
                                          uint32_t params_value_size,
                                          ndn_buffer_t* params_block)
{
  ndn_encoder_t encoder;
  encoder_init(&encoder, params_block->value, params_block->max_size);
  encoder_append_type(&encoder, TLV_SignedInterestParameters);
  encoder_append_length(&encoder, params_value_size);
  // application interest parameters
  if (interest->enable_Parameters) {
    encoder_append_type(&encoder, TLV_Parameters);
    encoder_append_length(&encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(&encoder, interest->parameters.value, interest->parameters.size);
  }
  // timestamp
  encoder_append_type(&encoder, TLV_SignedInterestTimestamp);
  encoder_append_length(&encoder, 4);
  encoder_append_uint32_value(&encoder, interest->signature_timestamp);
  // nounce
  encoder_append_type(&encoder, TLV_Nounce);
  encoder_append_length(&encoder, 4);
  encoder_append_uint32_value(&encoder, interest->signature_nounce);
  // signature info
  ndn_signature_info_tlv_encode(&encoder, &interest->signature);
  // set offset
  params_block->size = encoder.offset;
}

static void
_signed_interest_tlv_encode_after_signing(ndn_encoder_t* encoder, ndn_interest_t* interest,
                                          ndn_buffer_t* params_block)
{
  // can be prefix
  if (interest->enable_CanBePrefix) {
    encoder_append_type(encoder, TLV_CanBePrefix);
    encoder_append_length(encoder, 0);
  }
  // must be fresh
  if (interest->enable_MustBeFresh) {
    encoder_append_type(encoder, TLV_MustBeFresh);
    encoder_append_length(encoder, 0);
  }
  // nounce
  encoder_append_type(encoder, TLV_Nounce);
  encoder_append_length(encoder, 4);
  encoder_append_uint32_value(encoder, interest->nounce);
  // lifetime
  encoder_append_type(encoder, TLV_InterestLifetime);
  encoder_append_length(encoder, 2);
  encoder_append_uint16_value(encoder, interest->lifetime);
  if (interest->enable_HopLimit) {
    encoder_append_type(encoder, TLV_HopLimit);
    encoder_append_length(encoder, 1);
    encoder_append_byte_value(encoder, interest->hop_limit);
  }
  // signed interest parameters
  encoder_append_raw_buffer_value(encoder, params_block->value, params_block->size);
  // signature value
  ndn_signature_value_tlv_encode(encoder, &interest->signature);
}

/************************************************************/
/*  Definition of signed interest APIs                      */
/************************************************************/

int
ndn_signed_interest_tlv_encode_ecdsa_sign(ndn_encoder_t* encoder, ndn_interest_t* interest,
                                          const ndn_name_t* producer_identity,
                                          const ndn_ecc_prv_t* prv_key)
{
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_OVERSIZE;

  // set signature info
  _prepare_signature_info(interest, NDN_SIG_TYPE_ECDSA_SHA256, producer_identity, prv_key->key_id);

  // encode signed interest parameter block
  uint8_t params_block_value[NDN_SIGNED_INTEREST_PARAMS_MAX_SIZE] = {0};
  ndn_buffer_t params_block = {.value = params_block_value, .size = 0,
                              .max_size = NDN_SIGNED_INTEREST_PARAMS_MAX_SIZE};
  uint32_t params_value_size = _ndn_signed_interest_parameters_probe_value_size(interest);
  _prepare_signed_interest_parameters_block(interest, params_value_size, &params_block);

  // calculate digest component and append it to the name
  name_component_init(&interest->name.components[interest->name.components_size],
                      TLV_ParametersSha256DigestComponent);

  uint32_t used_bytes = 0;
  int result = ndn_signer_sha256_sign(params_block.value, params_block.size,
                                      interest->name.components[interest->name.components_size].value,
                                      NDN_NAME_COMPONENT_BUFFER_SIZE, &used_bytes);
  if (result < 0)
    return result;
  interest->name.components_size++;

  // start encoding
  uint32_t interest_block_size = _ndn_signed_interest_probe_block_size(interest, params_value_size);

  encoder_append_type(encoder, TLV_Interest);
  encoder_append_length(encoder, interest_block_size);
  uint32_t name_block_starting = encoder->offset;
  ndn_name_tlv_encode(encoder, &interest->name);
  uint32_t name_block_ending = encoder->offset;

  // calculate signature
  result = ndn_signer_ecdsa_sign(&encoder->output_value[name_block_starting],
                                 name_block_ending - name_block_starting,
                                 interest->signature.sig_value, interest->signature.sig_size,
                                 prv_key->key_value, prv_key->key_size,
                                 prv_key->curve_type, &used_bytes);
  if (result < 0)
    return result;

  // finish encoding
  _signed_interest_tlv_encode_after_signing(encoder, interest, &params_block);
  return 0;
}

int
ndn_signed_interest_tlv_encode_hmac_sign(ndn_encoder_t* encoder, ndn_interest_t* interest,
                                  const ndn_name_t* producer_identity, const ndn_hmac_key_t* hmac_key)
{
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_OVERSIZE;

  // set signature info
  _prepare_signature_info(interest, NDN_SIG_TYPE_HMAC_SHA256, producer_identity, hmac_key->key_id);

  // encode signed interest parameter block
  uint8_t params_block_value[NDN_SIGNED_INTEREST_PARAMS_MAX_SIZE] = {0};
  ndn_buffer_t params_block = {.value = params_block_value, .size = 0,
                              .max_size = NDN_SIGNED_INTEREST_PARAMS_MAX_SIZE};
  uint32_t params_value_size = _ndn_signed_interest_parameters_probe_value_size(interest);
  _prepare_signed_interest_parameters_block(interest, params_value_size, &params_block);

  // calculate digest component and append it to the name
  name_component_init(&interest->name.components[interest->name.components_size],
                      TLV_ParametersSha256DigestComponent);
  uint32_t used_bytes = 0;
  int result = ndn_signer_sha256_sign(params_block.value, params_block.size,
                  interest->name.components[interest->name.components_size].value,
                                      NDN_NAME_COMPONENT_BUFFER_SIZE, &used_bytes);
  if (result < 0)
    return result;
  interest->name.components_size++;

  // start encoding
  uint32_t interest_block_size = _ndn_signed_interest_probe_block_size(interest, params_value_size);

  encoder_append_type(encoder, TLV_Interest);
  encoder_append_length(encoder, interest_block_size);
  uint32_t name_block_starting = encoder->offset;
  ndn_name_tlv_encode(encoder, &interest->name);
  uint32_t name_block_ending = encoder->offset;

  // calculate signature
  result = ndn_signer_hmac_sign(&encoder->output_value[name_block_starting],
                                name_block_ending - name_block_starting,
                                interest->signature.sig_value, interest->signature.sig_size,
                                hmac_key->key_value, hmac_key->key_size, &used_bytes);
  if (result < 0)
    return result;

  // finish encoding
  _signed_interest_tlv_encode_after_signing(encoder, interest, &params_block);
  return 0;
}

int
ndn_signed_interest_tlv_encode_digest_sign(ndn_encoder_t* encoder, ndn_interest_t* interest)
{
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_OVERSIZE;

  // set signature info
  ndn_signature_init(&interest->signature, NDN_SIG_TYPE_DIGEST_SHA256);

  // encode signed interest parameter block
  uint8_t params_block_value[NDN_SIGNED_INTEREST_PARAMS_MAX_SIZE] = {0};
  ndn_buffer_t params_block = {.value = params_block_value, .size = 0,
                              .max_size = NDN_SIGNED_INTEREST_PARAMS_MAX_SIZE};
  uint32_t params_value_size = _ndn_signed_interest_parameters_probe_value_size(interest);
  _prepare_signed_interest_parameters_block(interest, params_value_size, &params_block);

  // calculate digest component and append it to the name
  name_component_init(&interest->name.components[interest->name.components_size],
                      TLV_ParametersSha256DigestComponent);
  uint32_t used_bytes = 0;
  int result = ndn_signer_sha256_sign(params_block.value, params_block.size,
                  interest->name.components[interest->name.components_size].value,
                                      NDN_NAME_COMPONENT_BUFFER_SIZE, &used_bytes);
  if (result < 0)
    return result;
  interest->name.components_size++;

  // start encoding
  uint32_t interest_block_size = _ndn_signed_interest_probe_block_size(interest, params_value_size);

  encoder_append_type(encoder, TLV_Interest);
  encoder_append_length(encoder, interest_block_size);
  uint32_t name_block_starting = encoder->offset;
  ndn_name_tlv_encode(encoder, &interest->name);
  uint32_t name_block_ending = encoder->offset;

  // calculate signature
  result = ndn_signer_sha256_sign(&encoder->output_value[name_block_starting],
                                  name_block_ending - name_block_starting,
                                  interest->signature.sig_value, interest->signature.sig_size,
                                  &used_bytes);
  if (result < 0)
    return result;

  // finish encoding
  _signed_interest_tlv_encode_after_signing(encoder, interest, &params_block);
  return 0;
}

int
ndn_signed_interest_ecdsa_verify(const ndn_interest_t* interest, const ndn_ecc_pub_t* pub_key)
{
  uint8_t name_block[NDN_NAME_MAX_BLOCK_SIZE];
  ndn_encoder_t encoder;
  encoder_init(&encoder, name_block, NDN_NAME_MAX_BLOCK_SIZE);
  ndn_name_tlv_encode(&encoder, &interest->name);
  int result = ndn_verifier_ecdsa_verify(encoder.output_value, encoder.offset,
                                         interest->signature.sig_value, interest->signature.sig_size,
                                         pub_key->key_value,
                                         pub_key->key_size, pub_key->curve_type);
  if (result)
    return result;
  return 0;
}

int
ndn_signed_interest_hmac_verify(const ndn_interest_t* interest, const ndn_hmac_key_t* hmac_key)
{
  uint8_t name_block[NDN_NAME_MAX_BLOCK_SIZE];
  ndn_encoder_t encoder;
  encoder_init(&encoder, name_block, NDN_NAME_MAX_BLOCK_SIZE);
  ndn_name_tlv_encode(&encoder, &interest->name);
  int result = ndn_verifier_hmac_verify(encoder.output_value, encoder.offset,
                                        interest->signature.sig_value, interest->signature.sig_size,
                                        hmac_key->key_value, hmac_key->key_size);
  if (result)
    return result;
  return 0;
}

int
ndn_signed_interest_digest_verify(const ndn_interest_t* interest)
{
  uint8_t name_block[NDN_NAME_MAX_BLOCK_SIZE];
  ndn_encoder_t encoder;
  encoder_init(&encoder, name_block, NDN_NAME_MAX_BLOCK_SIZE);
  ndn_name_tlv_encode(&encoder, &interest->name);

  int result = ndn_verifier_sha256_verify(encoder.output_value, encoder.offset,
                                          interest->signature.sig_value, interest->signature.sig_size);
  if (result)
    return result;
  return 0;
}
