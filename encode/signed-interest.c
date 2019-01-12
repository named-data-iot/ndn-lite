/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "signed-interest.h"
#include "../security/ndn-lite-hmac.h"
#include "../security/ndn-lite-sha.h"
#include "../security/ndn-lite-ecc.h"

/************************************************************/
/*  Helper functions for Signed Interest APIs               */
/*  Not supposed to be used by library users                */
/************************************************************/

static void
_prepare_signature_info(ndn_interest_t* interest, uint8_t signature_type,
                        const ndn_name_t* identity, uint32_t key_id,
                        uint32_t signature_info_nonce, uint64_t timestamp)
{
  uint8_t raw_key_id[4] = {0};
  raw_key_id[0] = (key_id >> 24) & 0xFF;
  raw_key_id[1] = (key_id >> 16) & 0xFF;
  raw_key_id[2] = (key_id >> 8) & 0xFF;
  raw_key_id[3] = key_id & 0xFF;

  ndn_signature_init(&interest->signature, signature_type);
  ndn_signature_set_key_locator(&interest->signature, identity);

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

  // set signature nonce
  ndn_signature_set_signature_info_nonce(&interest->signature, signature_info_nonce);

  // set timestamp
  ndn_signature_set_timestamp(&interest->signature, timestamp);
}

/************************************************************/
/*  Definition of signed interest APIs                      */
/************************************************************/

int
ndn_signed_interest_ecdsa_sign(ndn_interest_t* interest,
                               const ndn_name_t* identity, const ndn_ecc_prv_t* prv_key)
{
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_OVERSIZE;

  // set signature info
  // TODO added by Zhiyi: replaced with real timestamp and nonce
  _prepare_signature_info(interest, NDN_SIG_TYPE_ECDSA_SHA256, identity, prv_key->key_id, 0, 0);

  // update signature value and append the ending name component
  // prepare temp buffer to calculate signature value and the ending name component
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);
  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size; i++) {
    name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (interest->enable_Parameters) {
    encoder_append_type(&temp_encoder, TLV_Parameters);
    encoder_append_length(&temp_encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
  }
  ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;

  // calculate signature
  // signature is calculated over Name + Parameters + SignatureInfo
  uint32_t used_bytes = 0;
  int result = NDN_SUCCESS;
  result = ndn_ecdsa_sign(temp_encoder.output_value, siginfo_block_ending,
                          interest->signature.sig_value, NDN_SIGNATURE_BUFFER_SIZE,
                          prv_key, prv_key->curve_type, &used_bytes);
  interest->signature.sig_size = used_bytes;
  if (result < 0)
    return result;
  ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);

  // calculate the SignedInterestSha256DigestComponent
  // signature is calculated over Name + Parameters + SignatureInfo
  name_component_init(&interest->name.components[interest->name.components_size],
                      TLV_SignedInterestSha256DigestComponent);
  result = ndn_sha256_sign(&temp_encoder.output_value[param_block_starting],
                           temp_encoder.offset - param_block_starting,
                           interest->name.components[interest->name.components_size].value,
                           NDN_NAME_COMPONENT_BUFFER_SIZE, &used_bytes);
  interest->name.components[interest->name.components_size].size = used_bytes;
  interest->name.components_size++;
  if (result < 0)
    return result;
  interest->is_SignedInterest = 1;
  return NDN_SUCCESS;
}

int
ndn_signed_interest_hmac_sign(ndn_interest_t* interest,
                              const ndn_name_t* identity, const ndn_hmac_key_t* hmac_key)
{
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_OVERSIZE;

  // set signature info
  // TODO added by Zhiyi: replaced with real timestamp and nonce
  _prepare_signature_info(interest, NDN_SIG_TYPE_HMAC_SHA256, identity, hmac_key->key_id, 0, 0);

  // update signature value and append the ending name component
  // prepare temp buffer to calculate signature value and the ending name component
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);
  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size; i++) {
    name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (interest->enable_Parameters) {
    encoder_append_type(&temp_encoder, TLV_Parameters);
    encoder_append_length(&temp_encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
  }
  ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;

  // calculate signature
  // signature is calculated over Name + Parameters + SignatureInfo
  uint32_t used_bytes = 0;
  int result = NDN_SUCCESS;
  result = ndn_hmac_sign(temp_encoder.output_value, siginfo_block_ending,
                         interest->signature.sig_value, NDN_SIGNATURE_BUFFER_SIZE,
                         hmac_key, &used_bytes);
  interest->signature.sig_size = used_bytes;
  if (result < 0)
    return result;
  ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);

  // calculate the SignedInterestSha256DigestComponent
  // signature is calculated over Name + Parameters + SignatureInfo
  name_component_init(&interest->name.components[interest->name.components_size],
                      TLV_SignedInterestSha256DigestComponent);
  result = ndn_sha256_sign(&temp_encoder.output_value[param_block_starting],
                           temp_encoder.offset - param_block_starting,
                           interest->name.components[interest->name.components_size].value,
                           NDN_NAME_COMPONENT_BUFFER_SIZE, &used_bytes);
  interest->name.components[interest->name.components_size].size = used_bytes;
  interest->name.components_size++;
  if (result < 0)
    return result;
  interest->is_SignedInterest = 1;
  return NDN_SUCCESS;
}

int
ndn_signed_interest_digest_sign(ndn_interest_t* interest)
{
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_OVERSIZE;

  // set signature info
  ndn_signature_init(&interest->signature, NDN_SIG_TYPE_DIGEST_SHA256);
  // set signature nonce
  ndn_signature_set_signature_info_nonce(&interest->signature, 0);
  // set timestamp
  ndn_signature_set_timestamp(&interest->signature, 0);

  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);
  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size; i++) {
    name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (interest->enable_Parameters) {
    encoder_append_type(&temp_encoder, TLV_Parameters);
    encoder_append_length(&temp_encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
  }
  ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;

  // calculate signature
  // signature is calculated over Name + Parameters + SignatureInfo
  uint32_t used_bytes = 0;
  int result = NDN_SUCCESS;
  result = ndn_sha256_sign(temp_encoder.output_value, siginfo_block_ending,
                           interest->signature.sig_value, NDN_SIGNATURE_BUFFER_SIZE,
                           &used_bytes);
  interest->signature.sig_size = used_bytes;
  if (result < 0)
    return result;
  ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);

  // calculate the SignedInterestSha256DigestComponent
  // signature is calculated over Name + Parameters + SignatureInfo
  name_component_init(&interest->name.components[interest->name.components_size],
                      TLV_SignedInterestSha256DigestComponent);
  result = ndn_sha256_sign(&temp_encoder.output_value[param_block_starting],
                           temp_encoder.offset - param_block_starting,
                           interest->name.components[interest->name.components_size].value,
                           NDN_NAME_COMPONENT_BUFFER_SIZE, &used_bytes);
  interest->name.components[interest->name.components_size].size = used_bytes;
  interest->name.components_size++;
  if (result < 0)
    return result;
  interest->is_SignedInterest = 1;
  return NDN_SUCCESS;
}

int
ndn_signed_interest_ecdsa_verify(const ndn_interest_t* interest, const ndn_ecc_pub_t* pub_key)
{
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);

  // the signing input starts at Name's Value (V) excluding the ending component
  for (size_t i = 0; i < interest->name.components_size - 1; i++) {
    name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (interest->enable_Parameters) {
    encoder_append_type(&temp_encoder, TLV_Parameters);
    encoder_append_length(&temp_encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
  }
  ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;
  ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);

  int result = ndn_ecdsa_verify(temp_encoder.output_value, siginfo_block_ending,
                                interest->signature.sig_value, interest->signature.sig_size,
                                pub_key, pub_key->curve_type);
  if (result < 0)
    return result;

  result = ndn_sha256_verify(&temp_encoder.output_value[param_block_starting],
                             temp_encoder.offset - param_block_starting,
                             interest->name.components[interest->name.components_size - 1].value,
                             interest->name.components[interest->name.components_size - 1].size);
  if (result < 0)
    return NDN_SEC_SIGNED_INTEREST_INVALID_DIGEST;
  return NDN_SUCCESS;
}

int
ndn_signed_interest_hmac_verify(const ndn_interest_t* interest, const ndn_hmac_key_t* hmac_key)
{
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);

  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size - 1; i++) {
    name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (interest->enable_Parameters) {
    encoder_append_type(&temp_encoder, TLV_Parameters);
    encoder_append_length(&temp_encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
  }
  ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;
  ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);

  int result = ndn_hmac_verify(temp_encoder.output_value, siginfo_block_ending,
                               interest->signature.sig_value, interest->signature.sig_size,
                               hmac_key);
  if (result < 0)
    return result;

  result = ndn_sha256_verify(&temp_encoder.output_value[param_block_starting],
                             temp_encoder.offset - param_block_starting,
                             interest->name.components[interest->name.components_size - 1].value,
                             interest->name.components[interest->name.components_size - 1].size);
  if (result < 0)
    return NDN_SEC_SIGNED_INTEREST_INVALID_DIGEST;
  return NDN_SUCCESS;
}

int
ndn_signed_interest_digest_verify(const ndn_interest_t* interest)
{
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);

  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size - 1; i++) {
    name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (interest->enable_Parameters) {
    encoder_append_type(&temp_encoder, TLV_Parameters);
    encoder_append_length(&temp_encoder, interest->parameters.size);
    encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
  }
  ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;
  ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);

  int result = ndn_sha256_verify(temp_encoder.output_value, siginfo_block_ending,
                                 interest->signature.sig_value, interest->signature.sig_size);

  if (result < 0)
    return result;

  result = ndn_sha256_verify(&temp_encoder.output_value[param_block_starting],
                             temp_encoder.offset - param_block_starting,
                             interest->name.components[interest->name.components_size - 1].value,
                             interest->name.components[interest->name.components_size - 1].size);
  if (result < 0)
    return NDN_SEC_SIGNED_INTEREST_INVALID_DIGEST;
  return NDN_SUCCESS;
}
