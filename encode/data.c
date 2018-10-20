#include "data.h"

int
ndn_data_prepare_unsigned_block(ndn_encoder_t* encoder, const ndn_data_t* data)
{
  // name
  ndn_name_tlv_encode(&encoder, data->name);

  // meta info
  ndn_metainfo_tlv_encode(&encoder, data->metainfo);

  // content
  encoder_append_type(&encoder, TLV_Content);
  encoder_append_length(&encoder, data->content_size);
  encoder_append_raw_buffer_value(&encoder, data->content_value, data->content_size);

  // signature info
  ndn_signature_info_tlv_encode(&encoder, data->signature);
  return 0;
}

// int
// ndn_data_tlv_encode_digest_sign(const ndn_data_t* data)
// {
//   ndn_encoder_t encoder;
//   encoder_init(&encoder, block_value, block_max_size);

//   // set signature info
//   data->signature.sig_type = 0;
//   data->signature.sig_size = 0;
//   data->signature.

//   encoder_append_type(&encoder, TLV_Data);
//   encoder_append_length(&encoder, );

//   return 0;
// }

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
