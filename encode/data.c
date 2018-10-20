#include "data.h"
#include "../security/sign-verify.h"

#include <stdio.h>

int
ndn_data_prepare_unsigned_block(ndn_encoder_t* encoder, const ndn_data_t* data)
{
  // name
  int result = ndn_name_tlv_encode(encoder, &data->name);
  printf("name encode result %d\n", result);
  printf("encoder offset: %d\n", (int) encoder->offset);

  // meta info
  ndn_metainfo_tlv_encode(encoder, &data->metainfo);
  printf("encoder offset: %d\n", (int) encoder->offset);

  // content
  encoder_append_type(encoder, TLV_Content);
  encoder_append_length(encoder, data->content_size);
  encoder_append_raw_buffer_value(encoder, data->content_value, data->content_size);
  printf("encoder offset: %d\n", (int) encoder->offset);

  // signature info
  ndn_signature_info_tlv_encode(encoder, &data->signature);
  printf("encoder offset: %d\n", (int) encoder->offset);

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
  int result = ndn_signer_sha256_sign(&signer);
  printf("sign result %d\n", result);

  // finish encoding
  ndn_signature_value_tlv_encode(encoder, &data->signature);
  printf("encoder offset: %d\n", (int) encoder->offset);

  return 0;
}

// int
// ndn_data_tlv_encode_ecdsa_sign(const ndn_data_t* data, const ndn_name_t* producer_identity,
//                                const ndn_ecc_prv_t* prv_key);

// int
// ndn_data_tlv_encode_hmac_sign(const ndn_data_t* data, const ndn_name_t* producer_identity,
//                                const ndn_hmac_key_t* hmac_key);

// int
// ndn_data_tlv_decode(const ndn_data_t* data, const uint8_t* block_value, uint32_t block_size)
// {
//   ndn_decoder_t decoder;
//   decoder_init(&decoder, block_value, block_size);

//   return 0;
// }
