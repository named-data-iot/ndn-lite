/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "data.h"
#include "../security/ndn-lite-hmac.h"
#include "../security/ndn-lite-sha.h"
#include "../security/ndn-lite-aes.h"
#include "../security/ndn-lite-ecc.h"
#include "encrypted-payload.h"
#include "key-storage.h"
#include "../ndn-error-code.h"
#include "../util/uniform-time.h"

#define ENABLE_NDN_LOG_INFO 0
#define ENABLE_NDN_LOG_DEBUG 1
#define ENABLE_NDN_LOG_ERROR 0

#include "../util/logger.h"

/************************************************************/
/*  Helper functions for signed interest APIs               */
/*  Not supposed to be used by library users                */
/************************************************************/

#if ENABLE_NDN_LOG_DEBUG
static ndn_time_us_t m_measure_tp1 = 0;
static ndn_time_us_t m_measure_tp2 = 0;
#endif

// this function should be invoked only after data's signature
// info has been initialized
static int
_ndn_data_prepare_unsigned_block(ndn_encoder_t* encoder, const ndn_data_t* data)
{
  int ret_val = -1;
  // name
  ret_val = ndn_name_tlv_encode(encoder, &data->name);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // meta info
  ret_val = ndn_metainfo_tlv_encode(encoder, &data->metainfo);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // content
  ret_val = encoder_append_type(encoder, TLV_Content);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, data->content_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_raw_buffer_value(encoder, data->content_value, data->content_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // signature info
  ret_val = ndn_signature_info_tlv_encode(encoder, &data->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  return NDN_SUCCESS;
}

static void
_prepare_signature_info(ndn_data_t* data, uint8_t signature_type,
                        const ndn_name_t* producer_identity, uint32_t key_id)
{
  uint8_t raw_key_id[4] = {0};
  raw_key_id[0] = (key_id >> 24) & 0xFF;
  raw_key_id[1] = (key_id >> 16) & 0xFF;
  raw_key_id[2] = (key_id >> 8) & 0xFF;
  raw_key_id[3] = key_id & 0xFF;

  ndn_signature_init(&data->signature, false);
  ndn_signature_set_signature_type(&data->signature, signature_type);
  ndn_signature_set_key_locator(&data->signature, producer_identity);

  // append /KEY and /<KEY-ID> in key locator name
  char key_comp_string[] = "KEY";
  int pos = data->signature.key_locator_name.components_size;
  name_component_from_string(&data->signature.key_locator_name.components[pos],
                             key_comp_string, sizeof(key_comp_string));
  data->signature.key_locator_name.components_size++;
  pos = data->signature.key_locator_name.components_size;
  name_component_from_buffer(&data->signature.key_locator_name.components[pos],
                             TLV_GenericNameComponent, raw_key_id, 4);
  data->signature.key_locator_name.components_size++;
}

/************************************************************/
/*  Definition of signed interest APIs                      */
/************************************************************/

int
ndn_data_tlv_encode(ndn_encoder_t* encoder, ndn_data_t* data)
{
  int ret_val = -1;
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
  ret_val = encoder_append_type(encoder, TLV_Data);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, data_buffer_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // name
  ret_val = ndn_name_tlv_encode(encoder, &data->name);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // meta info
  ret_val = ndn_metainfo_tlv_encode(encoder, &data->metainfo);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // content
  ret_val = encoder_append_type(encoder, TLV_Content);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, data->content_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_raw_buffer_value(encoder, data->content_value, data->content_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // signature info
  ret_val = ndn_signature_info_tlv_encode(encoder, &data->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  // signature value
  ret_val = ndn_signature_value_tlv_encode(encoder, &data->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  return 0;
}

int
ndn_data_tlv_encode_digest_sign(ndn_encoder_t* encoder, ndn_data_t* data)
{
  int ret_val = -1;
  // set signature info
  ret_val = ndn_signature_init(&data->signature, false);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = ndn_signature_set_signature_type(&data->signature, NDN_SIG_TYPE_DIGEST_SHA256);
  if (ret_val != NDN_SUCCESS) return ret_val;

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
  ret_val = encoder_append_type(encoder, TLV_Data);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, data_buffer_size);
  if (ret_val != NDN_SUCCESS) return ret_val;

  uint32_t sign_input_starting = encoder->offset;
  ret_val = _ndn_data_prepare_unsigned_block(encoder, data);
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint32_t sign_input_ending = encoder->offset;

  // sign data
  uint32_t used_bytes = 0;
  int result = ndn_sha256_sign(encoder->output_value + sign_input_starting,
                               sign_input_ending - sign_input_starting,
                               data->signature.sig_value, data->signature.sig_size,
                               &used_bytes);
  if (result < 0) return result;

  // finish encoding
  ret_val = ndn_signature_value_tlv_encode(encoder, &data->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;

  return 0;
}

int
ndn_data_tlv_encode_ecdsa_sign(ndn_encoder_t* encoder, ndn_data_t* data,
                               const ndn_name_t* producer_identity, const ndn_ecc_prv_t* prv_key)
{
#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  int ret_val = -1;

  // ecdsa signing is a special case; the length of the packet cannot be known until after the signature
  // is generated, so the data's unsigned block must be prepared and signed, and then the data tlv type
  // and length can be added

  // set signature info
  _prepare_signature_info(data, NDN_SIG_TYPE_ECDSA_SHA256, producer_identity, prv_key->key_id);

  // start constructing the packet, leaving enough room for the maximum potential size of the
  // data tlv type and length; the finished packet will be memmoved to the beginning of the
  // encoder's buffer
  uint32_t initial_offset = NDN_TLV_TYPE_FIELD_MAX_SIZE + NDN_TLV_LENGTH_FIELD_MAX_SIZE;
  ret_val = encoder_move_forward(encoder, initial_offset);
  if (ret_val != NDN_SUCCESS) return ret_val;

  uint32_t sign_input_starting = encoder->offset;
  ret_val = _ndn_data_prepare_unsigned_block(encoder, data);
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint32_t sign_input_ending = encoder->offset;

  // sign data
  uint32_t sig_len = 0;
  int result = ndn_ecdsa_sign(encoder->output_value + sign_input_starting,
                              sign_input_ending - sign_input_starting,
                              data->signature.sig_value, data->signature.sig_size,
                              prv_key, &sig_len);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("DATA-PKT-ECDSA-SIGN: %lluus\n", m_measure_tp2 - m_measure_tp1);
#endif

  uint32_t data_buffer_size = ndn_name_probe_block_size(&data->name);
  // meta info
  data_buffer_size += ndn_metainfo_probe_block_size(&data->metainfo);
  // content
  data_buffer_size += encoder_probe_block_size(TLV_Content, data->content_size);
  // signature info
  data_buffer_size += ndn_signature_info_probe_block_size(&data->signature);
  // signature value
  data_buffer_size += encoder_probe_block_size(TLV_SignatureValue, sig_len);

  // add the data's tlv type and length
  uint32_t data_tlv_length_field_size = encoder_get_var_size(data_buffer_size);
  encoder->offset = sign_input_starting - data_tlv_length_field_size;
  ret_val = encoder_append_length(encoder, data_buffer_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint32_t data_tlv_type_field_size = encoder_get_var_size(TLV_Data);
  encoder->offset -= (data_tlv_length_field_size + data_tlv_type_field_size);
  ret_val = encoder_append_type(encoder, TLV_Data);
  if (ret_val != NDN_SUCCESS) return ret_val;

  // memmove the constructed packet (excluding signature tlv block) to the beginning of the encoder
  // buffer
  uint32_t data_size_without_signature = data_tlv_type_field_size + data_tlv_length_field_size +
                                         data_buffer_size;
  memmove(encoder->output_value,
          encoder->output_value + initial_offset -
            (data_tlv_type_field_size + data_tlv_length_field_size),
          data_size_without_signature);

  if (result < 0)
    return result;

  uint32_t sig_tlv_type_field_size = encoder_get_var_size(TLV_SignatureValue);
  uint32_t sig_tlv_length_field_size = encoder_get_var_size(sig_len);

  // reset the encoder's offset to be at the beginning of the signature tlv block
  encoder->offset = 0;
  encoder->offset += data_tlv_type_field_size +
                     data_tlv_length_field_size +
                     data_buffer_size -
                     sig_len -
                     sig_tlv_type_field_size -
                     sig_tlv_length_field_size;

  // set the signature size of the signature to the size of the ASN.1 encoded ecdsa signature
  data->signature.sig_size = sig_len;

  // finish encoding
  ret_val = ndn_signature_value_tlv_encode(encoder, &data->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
  NDN_LOG_DEBUG("DATA-PKT-ENCODING: %lluus\n", m_measure_tp1 - m_measure_tp2);
#endif

  return 0;
}

int
ndn_data_tlv_encode_hmac_sign(ndn_encoder_t* encoder, ndn_data_t* data,
                              const ndn_name_t* producer_identity, const ndn_hmac_key_t* hmac_key)
{
  int ret_val = -1;
  // set signature info
  _prepare_signature_info(data, NDN_SIG_TYPE_HMAC_SHA256, producer_identity, hmac_key->key_id);
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
  ret_val = encoder_append_type(encoder, TLV_Data);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, data_buffer_size);
  if (ret_val != NDN_SUCCESS) return ret_val;

  uint32_t sign_input_starting = encoder->offset;
  ret_val = _ndn_data_prepare_unsigned_block(encoder, data);
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint32_t sign_input_ending = encoder->offset;

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  // sign data
  uint32_t used_bytes = 0;
  int result = ndn_hmac_sign(encoder->output_value + sign_input_starting,
                             sign_input_ending - sign_input_starting,
                             data->signature.sig_value, data->signature.sig_size,
                             hmac_key, &used_bytes);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("DATA-PKT-HMAC-SIGN: %lluus\n", m_measure_tp2 - m_measure_tp1);
#endif

  if (result < 0)
    return result;

  // finish encoding
  ret_val = ndn_signature_value_tlv_encode(encoder, &data->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;

  return 0;
}

int
ndn_data_tlv_decode_no_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                              uint32_t* be_signed_start, uint32_t* be_signed_end)
{
  int ret_val = -1;
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);

  uint32_t probe;
  ret_val = decoder_get_type(&decoder, &probe);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = decoder_get_length(&decoder, &probe);
  if (ret_val != NDN_SUCCESS) return ret_val;
  if (be_signed_start != NULL)
    *be_signed_start = decoder.offset;

  // name
  ret_val = ndn_name_tlv_decode(&decoder, &data->name);
  if (ret_val != NDN_SUCCESS) return ret_val;

  // meta info
  ret_val = ndn_metainfo_tlv_decode(&decoder, &data->metainfo);
  if (ret_val != NDN_SUCCESS) return ret_val;

  // content
  ret_val = decoder_get_type(&decoder, &probe);
  if (ret_val != NDN_SUCCESS) return ret_val;
  switch(probe)
  {
    case TLV_Content:
      ret_val = decoder_get_length(&decoder, &probe);
      if (ret_val != NDN_SUCCESS) return ret_val;
      if (probe > NDN_CONTENT_BUFFER_SIZE) {
        return NDN_OVERSIZE;
      }
      data->content_size = probe;
      ret_val = decoder_get_raw_buffer_value(&decoder, data->content_value, data->content_size);
      if (ret_val != NDN_SUCCESS) return ret_val;
      break;

    case TLV_SignatureInfo:
      data->content_size = 0;
      ret_val = decoder_move_backward(&decoder, 1);
      if (ret_val != NDN_SUCCESS) return ret_val;
      break;

    default:
      return NDN_WRONG_TLV_TYPE;
  }

  // signature info
  ret_val = ndn_signature_info_tlv_decode(&decoder, &data->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  if (be_signed_end != NULL)
    *be_signed_end = decoder.offset;

  // signature value
  ret_val = ndn_signature_value_tlv_decode(&decoder, &data->signature);
  if (ret_val != NDN_SUCCESS) return ret_val;
  return NDN_SUCCESS;
}


int
ndn_data_tlv_decode_digest_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size)
{
  uint32_t be_signed_start, be_signed_end;
  ndn_data_tlv_decode_no_verify(data, block_value, block_size, &be_signed_start, &be_signed_end);
  int result = ndn_sha256_verify(block_value + be_signed_start, be_signed_end - be_signed_start,
                                 data->signature.sig_value, data->signature.sig_size);
  if (result == NDN_SUCCESS)
    return NDN_SUCCESS;
  else
    return NDN_SEC_FAIL_VERIFY_SIG;
}

int
ndn_data_tlv_decode_ecdsa_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                                 const ndn_ecc_pub_t* pub_key)
{
#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  uint32_t be_signed_start, be_signed_end;
  ndn_data_tlv_decode_no_verify(data, block_value, block_size, &be_signed_start, &be_signed_end);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("DATA-PKT-DECODING: %lluus\n", m_measure_tp2 - m_measure_tp1);
#endif

  int result = ndn_ecdsa_verify(block_value + be_signed_start, be_signed_end - be_signed_start,
                                data->signature.sig_value, data->signature.sig_size, pub_key);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
  NDN_LOG_DEBUG("DATA-PKT-ECDSA-VERIFY: %lluus\n", m_measure_tp1 - m_measure_tp2);
#endif

  if (result == NDN_SUCCESS)
    return NDN_SUCCESS;
  else
    return result;
}

int
ndn_data_tlv_decode_hmac_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                                const ndn_hmac_key_t* hmac_key)
{
#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  uint32_t be_signed_start, be_signed_end;
  ndn_data_tlv_decode_no_verify(data, block_value, block_size, &be_signed_start, &be_signed_end);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("DATA-PKT-DECODING: %lluus\n", m_measure_tp2 - m_measure_tp1);
#endif

  int result = ndn_hmac_verify(block_value + be_signed_start, be_signed_end - be_signed_start,
                               data->signature.sig_value, data->signature.sig_size, hmac_key);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
  NDN_LOG_DEBUG("DATA-PKT-HMAC-VERIFY: %lluus\n", m_measure_tp1 - m_measure_tp2);
#endif

  if (result == 0)
    return 0;
  else
    return result;
}

int
ndn_data_set_encrypted_content(ndn_data_t* data, const uint8_t* content_value, uint32_t content_size,
                               const ndn_name_t* key_name, const uint8_t* iv, uint32_t iv_size)
{
  int ret_val = -1;
  uint32_t tlv_size = 0;
  tlv_size += ndn_name_probe_block_size(key_name);
  tlv_size += ndn_probe_encrypted_payload_length(content_size);
  if (tlv_size > NDN_CONTENT_BUFFER_SIZE)
    return NDN_OVERSIZE;

  // prepare output block
  memset(data->content_value, 0, NDN_CONTENT_BUFFER_SIZE);
  data->content_size = tlv_size;

  ndn_encoder_t encoder;
  encoder_init(&encoder, data->content_value, NDN_CONTENT_BUFFER_SIZE);

  // type: TLV_NAME
  ret_val = ndn_name_tlv_encode(&encoder, key_name);
  if (ret_val != NDN_SUCCESS) return ret_val;

  uint32_t used_size = 0;
  ret_val = ndn_gen_encrypted_payload(content_value, content_size,
                                      encoder.output_value + encoder.offset, &used_size,
                                      key_id_from_key_name(key_name), iv, iv_size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  return 0;
}

int
ndn_data_parse_encrypted_content(const ndn_data_t* data, uint8_t* payload_value, uint32_t* payload_used_size,
                                 ndn_name_t* key_name)
{
  int ret_val = -1;
  ndn_decoder_t decoder;
  decoder_init(&decoder, data->content_value, data->content_size);

  // type: TLV_NAME
  ret_val = ndn_name_tlv_decode(&decoder, key_name);
  if (ret_val != NDN_SUCCESS) return ret_val;

  ret_val = ndn_parse_encrypted_payload(decoder.input_value + decoder.offset, decoder.input_size - decoder.offset,
                                        payload_value, payload_used_size, key_id_from_key_name(key_name));
  if (ret_val != NDN_SUCCESS) return ret_val;
  return 0;
}
