#include "data.h"
#include "../security/sign-verify.h"

#include <stdio.h>

int
ndn_data_prepare_unsigned_block(ndn_encoder_t* encoder, const ndn_data_t* data)
{
  // name
  ndn_name_tlv_encode(encoder, &data->name);
  // meta info
  ndn_metainfo_tlv_encode(encoder, &data->metainfo);
  // content
  encoder_append_type(encoder, TLV_Content);
  encoder_append_length(encoder, data->content_size);
  encoder_append_raw_buffer_value(encoder, data->content_value, data->content_size);
  // signature info
  ndn_signature_info_tlv_encode(encoder, &data->signature);
  return 0;
}

int
ndn_data_tlv_encode_digest_sign(ndn_encoder_t* encoder, ndn_data_t* data)
{
  // set signature info
  ndn_signature_init(&data->signature, NDN_SIG_TYPE_DIGEST_SHA256);

  uint32_t data_buffer_size = ndn_name_probe_block_size(&data->name);
  // meta info
  data_buffer_size += ndn_metainfo_probe_block_size(&data->metainfo);
  // content
  data_buffer_size += encoder_probe_block_size(TLV_Content, data->content_size);
  // signature info
  data_buffer_size += ndn_signature_info_probe_block_size(&data->signature);
  // signature value
  data_buffer_size += ndn_signature_value_probe_block_size(&data->signature);

  // data T and L
  encoder_append_type(encoder, TLV_Data);
  encoder_append_length(encoder, data_buffer_size);

  uint32_t sign_input_starting = encoder->offset;
  ndn_data_prepare_unsigned_block(encoder, data);
  uint32_t sign_input_ending = encoder->offset;

  // sign data
  ndn_signer_t signer;
  ndn_signer_init(&signer, encoder->output_value + sign_input_starting,
                  sign_input_ending - sign_input_starting,
                  data->signature.sig_value, data->signature.sig_size);
  int result = ndn_signer_sha256_sign(&signer);
  if (result < 0)
    return result;

  // finish encoding
  ndn_signature_value_tlv_encode(encoder, &data->signature);
  return 0;
}

int
ndn_data_tlv_encode_ecdsa_sign(ndn_encoder_t* encoder, ndn_data_t* data,
                               const ndn_name_t* producer_identity, const ndn_ecc_prv_t* prv_key)
{
  // set signature info
  ndn_signature_init(&data->signature, NDN_SIG_TYPE_ECDSA_SHA256);

  data->signature.enable_KeyLocator = 1;
  data->signature.key_locator_name = *producer_identity;
  name_component_t key_component;
  char key_comp_string[] = "KEY";
  name_component_from_string(&key_component, key_comp_string, sizeof(key_comp_string));
  name_component_t key_id_component;
  name_component_from_buffer(&key_id_component, TLV_GenericNameComponent, prv_key->key_id, 4);
  ndn_name_append_component(&data->signature.key_locator_name, &key_component);
  ndn_name_append_component(&data->signature.key_locator_name, &key_id_component);

  uint32_t data_buffer_size = ndn_name_probe_block_size(&data->name);
  // meta info
  data_buffer_size += ndn_metainfo_probe_block_size(&data->metainfo);
  // content
  data_buffer_size += encoder_probe_block_size(TLV_Content, data->content_size);
  // signature info
  data_buffer_size += ndn_signature_info_probe_block_size(&data->signature);
  // signature value
  data_buffer_size += ndn_signature_value_probe_block_size(&data->signature);

  // data T and L
  encoder_append_type(encoder, TLV_Data);
  printf("encoder offset: %d\n", (int) encoder->offset);

  encoder_append_length(encoder, data_buffer_size);
  printf("encoder offset: %d\n", (int) encoder->offset);

  uint32_t sign_input_starting = encoder->offset;
  ndn_data_prepare_unsigned_block(encoder, data);
  uint32_t sign_input_ending = encoder->offset;

  printf("encoder offset: %d\n", (int) encoder->offset);

  // sign data
  ndn_signer_t signer;
  ndn_signer_init(&signer, encoder->output_value + sign_input_starting,
                  sign_input_ending - sign_input_starting,
                  data->signature.sig_value, data->signature.sig_size);
  int result = ndn_signer_ecdsa_sign(&signer, prv_key->key_value,
                                     prv_key->key_size, prv_key->curve_type);
  printf("sign result %d\n", result);
  if (result < 0)
    return result;

  // finish encoding
  ndn_signature_value_tlv_encode(encoder, &data->signature);
  printf("encoder offset: %d\n", (int) encoder->offset);

  return 0;
}

int
ndn_data_tlv_encode_hmac_sign(ndn_encoder_t* encoder, ndn_data_t* data,
                              const ndn_name_t* producer_identity, const ndn_hmac_key_t* hmac_key)
{
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

  uint32_t data_buffer_size = ndn_name_probe_block_size(&data->name);
  // meta info
  data_buffer_size += ndn_metainfo_probe_block_size(&data->metainfo);
  // content
  data_buffer_size += encoder_probe_block_size(TLV_Content, data->content_size);
  // signature info
  data_buffer_size += ndn_signature_info_probe_block_size(&data->signature);
  // signature value
  data_buffer_size += ndn_signature_value_probe_block_size(&data->signature);

  // data T and L
  encoder_append_type(encoder, TLV_Data);
  printf("encoder offset: %d\n", (int) encoder->offset);

  encoder_append_length(encoder, data_buffer_size);
  printf("encoder offset: %d\n", (int) encoder->offset);

  uint32_t sign_input_starting = encoder->offset;
  ndn_data_prepare_unsigned_block(encoder, data);
  uint32_t sign_input_ending = encoder->offset;

  printf("encoder offset: %d\n", (int) encoder->offset);

  // sign data
  ndn_signer_t signer;
  ndn_signer_init(&signer, encoder->output_value + sign_input_starting,
                  sign_input_ending - sign_input_starting,
                  data->signature.sig_value, data->signature.sig_size);
  int result = ndn_signer_hmac_sign(&signer, hmac_key->key_value, hmac_key->key_size);
  printf("sign result %d\n", result);
  if (result < 0)
    return result;

  // finish encoding
  ndn_signature_value_tlv_encode(encoder, &data->signature);
  printf("encoder offset: %d\n", (int) encoder->offset);

  return 0;
}

int
ndn_data_tlv_decode_no_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);

  uint32_t probe;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);

  // name
  ndn_name_tlv_decode(&decoder, &data->name);

  // meta info
  ndn_metainfo_tlv_decode(&decoder, &data->metainfo);

  // content
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &data->content_size);
  decoder_get_raw_buffer_value(&decoder, data->content_value, data->content_size);

  // signature info
  ndn_signature_info_tlv_decode(&decoder, &data->signature);

  // signature value
  int result = ndn_signature_value_tlv_decode(&decoder, &data->signature);
  if (result < 0)
    return result;
  else
    return 0;
}


int
ndn_data_tlv_decode_digest_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);

  uint32_t probe;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint32_t input_starting = decoder.offset;

  // name
  ndn_name_tlv_decode(&decoder, &data->name);

  // meta info
  ndn_metainfo_tlv_decode(&decoder, &data->metainfo);

  // content
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &data->content_size);
  decoder_get_raw_buffer_value(&decoder, data->content_value, data->content_size);

  // signature info
  ndn_signature_info_tlv_decode(&decoder, &data->signature);
  uint32_t input_ending = decoder.offset;

  // signature value
  ndn_signature_value_tlv_decode(&decoder, &data->signature);

  ndn_verifier_t verifier;
  ndn_verifier_init(&verifier, decoder.input_value + input_starting,
                    input_ending - input_starting,
                    data->signature.sig_value, data->signature.sig_size);
  int result = ndn_verifier_sha256_verify(&verifier);
  if (result == 0)
    return 0;
  else
    return result;
}

int
ndn_data_tlv_decode_ecdsa_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                                 const ndn_ecc_pub_t* pub_key)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);

  uint32_t probe;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint32_t input_starting = decoder.offset;

  // name
  ndn_name_tlv_decode(&decoder, &data->name);

  // meta info
  ndn_metainfo_tlv_decode(&decoder, &data->metainfo);

  // content
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &data->content_size);
  decoder_get_raw_buffer_value(&decoder, data->content_value, data->content_size);

  // signature info
  ndn_signature_info_tlv_decode(&decoder, &data->signature);
  uint32_t input_ending = decoder.offset;

  // signature value
  ndn_signature_value_tlv_decode(&decoder, &data->signature);

  ndn_verifier_t verifier;
  ndn_verifier_init(&verifier, decoder.input_value + input_starting,
                    input_ending - input_starting,
                    data->signature.sig_value, data->signature.sig_size);
  int result = ndn_verifier_ecdsa_verify(&verifier, pub_key->key_value,
                                         pub_key->key_size, pub_key->curve_type);
  if (result == 0)
    return 0;
  else
    return result;
}

int
ndn_data_tlv_decode_hmac_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                                const ndn_hmac_key_t* hmac_key)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);

  uint32_t probe;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint32_t input_starting = decoder.offset;

  // name
  ndn_name_tlv_decode(&decoder, &data->name);

  // meta info
  ndn_metainfo_tlv_decode(&decoder, &data->metainfo);

  // content
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &data->content_size);
  decoder_get_raw_buffer_value(&decoder, data->content_value, data->content_size);

  // signature info
  ndn_signature_info_tlv_decode(&decoder, &data->signature);
  uint32_t input_ending = decoder.offset;

  // signature value
  ndn_signature_value_tlv_decode(&decoder, &data->signature);

  ndn_verifier_t verifier;
  ndn_verifier_init(&verifier, decoder.input_value + input_starting,
                    input_ending - input_starting,
                    data->signature.sig_value, data->signature.sig_size);
  int result = ndn_verifier_hmac_verify(&verifier, hmac_key->key_value, hmac_key->key_size);
  if (result == 0)
    return 0;
  else
    return result;
}
