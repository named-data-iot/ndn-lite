/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "signed-interest.h"
#include "key-storage.h"
#include "../security/ndn-lite-hmac.h"
#include "../security/ndn-lite-sha.h"
#include "../security/ndn-lite-ecc.h"

/************************************************************/
/*  Helper functions for Signed Interest APIs               */
/*  Not supposed to be used by library users                */
/************************************************************/

static void
_prepare_signature_info(ndn_interest_t* interest, uint8_t signature_type,
                        const ndn_name_t* identity, uint32_t key_id)
{
  uint8_t raw_key_id[4] = {0};
  raw_key_id[0] = (key_id >> 24) & 0xFF;
  raw_key_id[1] = (key_id >> 16) & 0xFF;
  raw_key_id[2] = (key_id >> 8) & 0xFF;
  raw_key_id[3] = key_id & 0xFF;

  ndn_signature_init(&interest->signature, true);
  ndn_signature_set_signature_type(&interest->signature, signature_type);

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
  uint32_t signature_info_nonce = 0;
  ndn_rng((uint8_t*)&signature_info_nonce, sizeof(signature_info_nonce));
  ndn_signature_set_signature_nonce(&interest->signature, signature_info_nonce);

  // set timestamp
  ndn_signature_set_timestamp(&interest->signature, ndn_time_now_ms());
}

/************************************************************/
/*  Definition of signed interest APIs                      */
/************************************************************/

int
ndn_signed_interest_ecdsa_sign(ndn_interest_t* interest,
                               const ndn_name_t* identity, const ndn_ecc_prv_t* prv_key)
{
  int ret_val = -1;
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_OVERSIZE;

  // set signature info
  ndn_key_storage_t* keys = ndn_key_storage_get_instance();
  if (identity == NULL) {
    identity = &keys->self_identity;
  }
  if (prv_key == NULL) {
    prv_key = &keys->self_identity_key;
  }
  _prepare_signature_info(interest, NDN_SIG_TYPE_ECDSA_SHA256, identity, prv_key->key_id);

  // update signature value and append the ending name component
  // prepare temp buffer to calculate signature value and the ending name component
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);
  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size; i++) {
    ret_val = name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (ndn_interest_has_Parameters(interest)) {
    ret_val = encoder_append_type(&temp_encoder, TLV_ApplicationParameters);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(&temp_encoder, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  ret_val = ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;

  // calculate signature
  // signature is calculated over Name + Parameters + SignatureInfo
  uint32_t used_bytes = 0;
  int result = NDN_SUCCESS;
  result = ndn_ecdsa_sign(temp_encoder.output_value, siginfo_block_ending,
                          interest->signature.sig_value, NDN_SIGNATURE_BUFFER_SIZE,
                          prv_key, &used_bytes);
  if (result < 0) return result;
  interest->signature.sig_size = used_bytes;

  ret_val = ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;

  // calculate the TLV_ParametersSha256DigestComponent
  // component is calculated over Name + Parameters + SignatureInfo + SignatureValue
  result = ndn_sha256(&temp_encoder.output_value[param_block_starting],
                      temp_encoder.offset - param_block_starting,
                      interest->name.components[interest->name.components_size].value);
  if (result < 0) return result;
  interest->name.components[interest->name.components_size].type = TLV_ParametersSha256DigestComponent;
  interest->name.components[interest->name.components_size].size = NDN_SEC_SHA256_HASH_SIZE;
  interest->name.components_size++;
  BIT_SET(interest->flags, 7);
  return NDN_SUCCESS;
}

int
ndn_signed_interest_hmac_sign(ndn_interest_t* interest,
                              const ndn_name_t* identity, const ndn_hmac_key_t* hmac_key)
{
  int ret_val = -1;
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_OVERSIZE;

  // set signature info
  _prepare_signature_info(interest, NDN_SIG_TYPE_HMAC_SHA256, identity, hmac_key->key_id);

  // update signature value and append the ending name component
  // prepare temp buffer to calculate signature value and the ending name component
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);
  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size; i++) {
    ret_val = name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (ndn_interest_has_Parameters(interest)) {
    ret_val = encoder_append_type(&temp_encoder, TLV_ApplicationParameters);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(&temp_encoder, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  ret_val = ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;

  // calculate signature
  // signature is calculated over Name + Parameters + SignatureInfo
  uint32_t used_bytes = 0;
  int result = NDN_SUCCESS;
  result = ndn_hmac_sign(temp_encoder.output_value, siginfo_block_ending,
                         interest->signature.sig_value, NDN_SIGNATURE_BUFFER_SIZE,
                         hmac_key, &used_bytes);
  if (result < 0) return result;
  interest->signature.sig_size = used_bytes;

  ret_val = ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;

  // calculate the SignedInterestSha256DigestComponent
  // component is calculated over Name + Parameters + SignatureInfo + SignatureValue
  result = ndn_sha256(&temp_encoder.output_value[param_block_starting],
                      temp_encoder.offset - param_block_starting,
                      interest->name.components[interest->name.components_size].value);
  if (result < 0) return result;
  interest->name.components[interest->name.components_size].type = TLV_ParametersSha256DigestComponent;
  interest->name.components[interest->name.components_size].size = NDN_SEC_SHA256_HASH_SIZE;
  interest->name.components_size++;
  BIT_SET(interest->flags, 7);
  return NDN_SUCCESS;
}

int
ndn_signed_interest_digest_sign(ndn_interest_t* interest)
{
  int ret_val = -1;
  if (interest->name.components_size + 1 > NDN_NAME_COMPONENTS_SIZE)
    return NDN_OVERSIZE;

  // set signature info
  ndn_signature_init(&interest->signature, true);
  ndn_signature_set_signature_type(&interest->signature, NDN_SIG_TYPE_DIGEST_SHA256);
  // set signature nonce
  ndn_signature_set_signature_nonce(&interest->signature, 0);
  // set timestamp
  ndn_signature_set_timestamp(&interest->signature, 0);

  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);
  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size; i++) {
    ret_val = name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (ndn_interest_has_Parameters(interest)) {
    ret_val = encoder_append_type(&temp_encoder, TLV_ApplicationParameters);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(&temp_encoder, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  ret_val = ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;

  // calculate signature
  // signature is calculated over Name + Parameters + SignatureInfo
  uint32_t used_bytes = 0;
  int result = NDN_SUCCESS;
  result = ndn_sha256_sign(temp_encoder.output_value, siginfo_block_ending,
                           interest->signature.sig_value, NDN_SIGNATURE_BUFFER_SIZE,
                           &used_bytes);
  if (result < 0) return result;
  interest->signature.sig_size = used_bytes;

  ret_val = ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;

  // calculate the TLV_ParametersSha256DigestComponent
  // component is calculated over Name + Parameters + SignatureInfo + SignatureValue
  result = ndn_sha256(&temp_encoder.output_value[param_block_starting],
                      temp_encoder.offset - param_block_starting,
                      interest->name.components[interest->name.components_size].value);
  if (result < 0) return result;
  interest->name.components[interest->name.components_size].type = TLV_ParametersSha256DigestComponent;
  interest->name.components[interest->name.components_size].size = NDN_SEC_SHA256_HASH_SIZE;
  interest->name.components_size++;
  BIT_SET(interest->flags, 7);
  return NDN_SUCCESS;
}

int
ndn_signed_interest_ecdsa_verify(const ndn_interest_t* interest, const ndn_ecc_pub_t* pub_key)
{
  // check the signed Interest format
  if (!ndn_interest_is_signed(interest) ||
      interest->name.components[interest->name.components_size - 1].type != TLV_ParametersSha256DigestComponent) {
    return NDN_UNSUPPORTED_FORMAT;
  }
  int ret_val = -1;
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);

  // the signing input starts at Name's Value (V) excluding the ending component
  for (size_t i = 0; i < interest->name.components_size - 1; i++) {
    ret_val = name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (ndn_interest_has_Parameters(interest)) {
    ret_val = encoder_append_type(&temp_encoder, TLV_ApplicationParameters);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(&temp_encoder, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  ret_val = ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;
  ret_val = ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;

  int result = ndn_ecdsa_verify(temp_encoder.output_value, siginfo_block_ending,
                                interest->signature.sig_value, interest->signature.sig_size,
                                pub_key);
  if (result < 0) return result;

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
  // check the signed Interest format
  if (!ndn_interest_is_signed(interest) ||
      interest->name.components[interest->name.components_size - 1].type != TLV_ParametersSha256DigestComponent) {
    return NDN_UNSUPPORTED_FORMAT;
  }
  int ret_val = -1;
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);

  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size - 1; i++) {
    ret_val = name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (ndn_interest_has_Parameters(interest)) {
    ret_val = encoder_append_type(&temp_encoder, TLV_ApplicationParameters);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(&temp_encoder, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  ret_val = ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;
  ret_val = ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  int result = ndn_hmac_verify(temp_encoder.output_value, siginfo_block_ending,
                               interest->signature.sig_value, interest->signature.sig_size,
                               hmac_key);
  if (result < 0) return result;

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
  // check the signed Interest format
  if (!ndn_interest_is_signed(interest) ||
      interest->name.components[interest->name.components_size - 1].type != TLV_ParametersSha256DigestComponent) {
    return NDN_UNSUPPORTED_FORMAT;
  }
  int ret_val = -1;
  uint8_t be_signed[NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE] = {0};
  ndn_encoder_t temp_encoder;
  encoder_init(&temp_encoder, be_signed, NDN_SIGNED_INTEREST_BE_SIGNED_MAX_SIZE);

  // the signing input starts at Name's Value (V)
  for (size_t i = 0; i < interest->name.components_size - 1; i++) {
    ret_val = name_component_tlv_encode(&temp_encoder, &interest->name.components[i]);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  // the digest input starts at parameters
  uint32_t param_block_starting = temp_encoder.offset;
  if (ndn_interest_has_Parameters(interest)) {
    ret_val = encoder_append_type(&temp_encoder, TLV_ApplicationParameters);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_length(&temp_encoder, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
    ret_val = encoder_append_raw_buffer_value(&temp_encoder, interest->parameters.value, interest->parameters.size);
    if (ret_val != NDN_SUCCESS) return ret_val;
  }
  ret_val = ndn_signature_info_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // the signing input ends at signature info
  uint32_t siginfo_block_ending = temp_encoder.offset;
  ret_val = ndn_signature_value_tlv_encode(&temp_encoder, &interest->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;

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
