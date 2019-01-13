/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sign-on-basic-client.h"

#include <string.h>

#include "../../../ndn-error-code.h"
#include "../../../ndn-constants.h"

#include "../../../encode/tlv.h"
#include "../../../encode/decoder.h"

#include "sign-on-basic-consts.h"
#include "security/sign-on-basic-sec-consts.h"
#include "sign-on-basic-impl-consts.h"
#include "variants/ecc_256/sign-on-basic-ecc-256-consts.h"

int sign_on_basic_client_init(
    uint8_t variant,
    struct sign_on_basic_client_t *sign_on_basic_client,
    const uint8_t *device_identifier_p, uint32_t device_identifier_len,
    const uint8_t *device_capabilities_p, uint32_t device_capabilities_len,
    const uint8_t *secure_sign_on_code_p,
    const uint8_t *KS_pub_p, uint32_t KS_pub_len,
    const uint8_t *KS_pri_p, uint32_t KS_pri_len) {
  switch (variant) {
    case SIGN_ON_BASIC_VARIANT_ECC_256:
      sign_on_basic_client->secure_sign_on_code_len = SIGN_ON_BASIC_ECC_256_SECURE_SIGN_ON_CODE_LENGTH;
      break;
    default:
      return NDN_SIGN_ON_BASIC_CLIENT_INIT_FAILED_UNRECOGNIZED_VARIANT;
      break;
  }

  int set_sec_intf_result = sign_on_basic_set_sec_intf(variant, sign_on_basic_client);
  if (set_sec_intf_result != NDN_SUCCESS)
    return NDN_SIGN_ON_BASIC_CLIENT_INIT_FAILED_TO_SET_SEC_INTF;

  memcpy(sign_on_basic_client->device_identifier_p, device_identifier_p, device_identifier_len);
  sign_on_basic_client->device_identifier_len = device_identifier_len;

  memcpy(sign_on_basic_client->device_capabilities_p, device_capabilities_p, device_capabilities_len);
  sign_on_basic_client->device_capabilities_len = device_capabilities_len;

  memcpy(sign_on_basic_client->secure_sign_on_code_p, secure_sign_on_code_p, 
    sign_on_basic_client->secure_sign_on_code_len);

  memcpy(sign_on_basic_client->KS_pub_p, KS_pub_p, KS_pub_len);
  sign_on_basic_client->KS_pub_len = KS_pub_len;

  memcpy(sign_on_basic_client->KS_pri_p, KS_pri_p, KS_pri_len);
  sign_on_basic_client->KS_pri_len = KS_pri_len;

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_NOT_STARTED;

  return NDN_SUCCESS;
}

int cnstrct_btstrp_rqst(uint8_t *buf_p, uint32_t buf_len,
    uint32_t *output_len_p,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  // generate N1 key pair here
  if (!sign_on_basic_client->sec_intf.gen_n1_keypair(
          sign_on_basic_client->N1_pub_p, SIGN_ON_BASIC_CLIENT_N1_PUB_MAX_LENGTH,
          &sign_on_basic_client->N1_pub_len,
          sign_on_basic_client->N1_pri_p, SIGN_ON_BASIC_CLIENT_N1_PRI_MAX_LENGTH,
          &sign_on_basic_client->N1_pri_len)) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_FAILED_TO_GENERATE_N1_KEYPAIR;
  }

  uint8_t digest_buffer[SIGN_ON_BASIC_SHA256_HASH_SIZE];

  int ndn_encoder_success = 0;
  uint32_t btstrp_rqst_tlv_val_len = 0;
  uint32_t btstrp_rqst_sig_tlv_val_len = 0;

  btstrp_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_DEVICE_IDENTIFIER,
                                                      sign_on_basic_client->device_identifier_len);
  btstrp_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_DEVICE_CAPABILITIES,
                                                      sign_on_basic_client->device_capabilities_len);
  btstrp_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_N1_PUB,
                                                      sign_on_basic_client->N1_pub_len);
  btstrp_rqst_sig_tlv_val_len = sign_on_basic_client->sec_intf.get_btstrp_rqst_sig_len();
  uint32_t btstrp_rqst_sig_tlv_len_field_size = encoder_get_var_size(btstrp_rqst_sig_tlv_val_len);
  uint32_t btstrp_rqst_sig_tlv_type_field_size = encoder_get_var_size(TLV_SSP_SIGNATURE);
  btstrp_rqst_tlv_val_len += btstrp_rqst_sig_tlv_type_field_size;
  btstrp_rqst_tlv_val_len += btstrp_rqst_sig_tlv_len_field_size;
  btstrp_rqst_tlv_val_len += btstrp_rqst_sig_tlv_val_len;

  uint32_t btstrp_rqst_tlv_type_field_size = encoder_get_var_size(TLV_SSP_BOOTSTRAPPING_REQUEST);
  uint32_t btstrp_rqst_tlv_len_field_size = encoder_get_var_size(btstrp_rqst_tlv_val_len);

  uint32_t btstrp_rqst_total_len = btstrp_rqst_tlv_val_len + btstrp_rqst_tlv_type_field_size + 
                                   btstrp_rqst_tlv_len_field_size;
  if (buf_len < btstrp_rqst_total_len) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_BUFFER_TOO_SHORT;
  }

  ndn_encoder_t encoder;
  encoder_init(&encoder, buf_p, buf_len);

  // append the bootstrapping request tlv type and length
  if (encoder_append_type(&encoder, TLV_SSP_BOOTSTRAPPING_REQUEST) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;   
  }
  if (encoder_append_length(&encoder, btstrp_rqst_tlv_val_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;   
  }
  
  // append the device identifier
  if (encoder_append_type(&encoder, TLV_SSP_DEVICE_IDENTIFIER) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, sign_on_basic_client->device_identifier_len) != ndn_encoder_success)  {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, sign_on_basic_client->device_identifier_p,
                                      sign_on_basic_client->device_identifier_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }

  // append the device capabilities
  if (encoder_append_type(&encoder, TLV_SSP_DEVICE_CAPABILITIES) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, sign_on_basic_client->device_capabilities_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, sign_on_basic_client->device_capabilities_p,
                                      sign_on_basic_client->device_capabilities_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }

  // append N1 pub
  if (encoder_append_type(&encoder, TLV_SSP_N1_PUB) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, sign_on_basic_client->N1_pub_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, sign_on_basic_client->N1_pub_p,
                                      sign_on_basic_client->N1_pub_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }

  uint8_t *sig_payload_begin = buf_p + btstrp_rqst_tlv_type_field_size + btstrp_rqst_tlv_len_field_size;
  uint32_t sig_payload_size = encoder.offset - btstrp_rqst_tlv_type_field_size - btstrp_rqst_tlv_len_field_size;

  // calculate the signature 
  uint8_t temp_sig_buf[SIG_GENERATION_BUF_LENGTH];
  uint32_t sig_size = 0;
  if (!sign_on_basic_client->sec_intf.gen_btstrp_rqst_sig(sign_on_basic_client->KS_pri_p,
                                                          sig_payload_begin, sig_payload_size,
                                                          temp_sig_buf, SIG_GENERATION_BUF_LENGTH, 
                                                          &sig_size)) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_FAILED_TO_GENERATE_SIG;
  }

  if (btstrp_rqst_sig_tlv_val_len != sig_size) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }

  encoder_append_type(&encoder, TLV_SSP_SIGNATURE);
  encoder_append_length(&encoder, sig_size);
  encoder_append_raw_buffer_value(&encoder, temp_sig_buf, sig_size);

  *output_len_p = encoder.offset;

  return NDN_SUCCESS;
  
}

int prcs_btstrp_rqst_rspns(const uint8_t *btstrp_rqst_rspns_buf_p,
    uint32_t btstrp_rqst_rspns_buf_len,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  // define pointers to data / lengths of data to be copied at the end, after processing is finished,
  // so that no internal state of the sign on basic client object is modified until after the whole
  // message has been processed successfully
  uint8_t *N2_pub_p;
  uint32_t N2_pub_len;
  uint8_t *trust_anchor_p;
  uint32_t trust_anchor_len;

  int ndn_decoder_success = 0;
  ndn_decoder_t decoder;
  decoder_init(&decoder, btstrp_rqst_rspns_buf_p, btstrp_rqst_rspns_buf_len);

  uint32_t current_tlv_type;
  uint32_t current_tlv_length;
  uint8_t *btstrp_rqst_rspns_tlv_val_buf_p;
  uint32_t btstrp_rqst_rspns_tlv_val_len;
  uint8_t *btstrp_rqst_rspns_tlv_sig_p;

  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_BTSTRP_RQST_RSPNS;
  }
  if (current_tlv_type != TLV_SSP_BOOTSTRAPPING_REQUEST_RESPONSE) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_BTSTRP_RQST_RSPNS;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_BTSTRP_RQST_RSPNS;
  }

  btstrp_rqst_rspns_tlv_val_buf_p = btstrp_rqst_rspns_buf_p + decoder.offset;
  btstrp_rqst_rspns_tlv_val_len = current_tlv_length;

  // check for the N2 pub tlv block and move the decoder offset past it
  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_N2_PUB;
  }
  if (current_tlv_type != TLV_SSP_N2_PUB) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_N2_PUB;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_N2_PUB;
  }
  N2_pub_p = btstrp_rqst_rspns_buf_p + decoder.offset;
  N2_pub_len = current_tlv_length;
  if (decoder_move_forward(&decoder, current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_N2_PUB;
  }

  // check for the trust anchor certificate tlv block and move the decoder offset past it
  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_TRUST_ANCHOR_CERT;
  }
  if (current_tlv_type != TLV_SSP_ANCHOR_CERTIFICATE) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_TRUST_ANCHOR_CERT;
  } 
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_TRUST_ANCHOR_CERT;
  }
  trust_anchor_p = btstrp_rqst_rspns_buf_p + decoder.offset;
  trust_anchor_len = current_tlv_length;
  if (decoder_move_forward(&decoder, current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_TRUST_ANCHOR_CERT;
  }

  // check for signature tlv block and move the decoder to its tlv value

  btstrp_rqst_rspns_tlv_sig_p = btstrp_rqst_rspns_buf_p + decoder.offset;

  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }
  if (current_tlv_type != TLV_SSP_SIGNATURE) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }

  const uint8_t *sig_begin = btstrp_rqst_rspns_buf_p + decoder.offset;
  uint32_t sig_len = current_tlv_length;
  const uint8_t *sig_payload_begin = btstrp_rqst_rspns_tlv_val_buf_p;
  uint32_t sig_payload_len = btstrp_rqst_rspns_tlv_sig_p - btstrp_rqst_rspns_tlv_val_buf_p;

  if (!sign_on_basic_client->sec_intf.vrfy_btstrp_rqst_rspns_sig(
          sig_payload_begin, sig_payload_len,
          sig_begin, sig_len,
          sign_on_basic_client->secure_sign_on_code_p,
          sign_on_basic_client->secure_sign_on_code_len)) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_VERIFY_SIGNATURE;
  }

  //***************************************************//

  if (!sign_on_basic_client->sec_intf.gen_kt(N2_pub_p, N2_pub_len,
                                             sign_on_basic_client->N1_pri_p, sign_on_basic_client->N1_pri_len,
                                             sign_on_basic_client->KT_p,
                                             SIGN_ON_BASIC_CLIENT_KT_MAX_LENGTH,
                                             &sign_on_basic_client->KT_len)) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_GENERATE_KT;
  }

  //***************************************************//

  // now that the entire bootstrapping request respone has been processed successfully, can modify internal state
  // of sign on client object
  memcpy(sign_on_basic_client->N2_pub_p, N2_pub_p, (size_t) N2_pub_len);
  sign_on_basic_client->N2_pub_len = N2_pub_len;
  memcpy(sign_on_basic_client->trust_anchor_cert_p, trust_anchor_p, (size_t) trust_anchor_len);
  sign_on_basic_client->trust_anchor_cert_len = trust_anchor_len;

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_PROCESSED_BOOTSTRAPPING_REQUEST_RESPONSE;
  return NDN_SUCCESS;
}

int cnstrct_cert_rqst(uint8_t *buf_p, uint32_t buf_len, uint32_t *output_len_p,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  uint8_t digest_buffer[SIGN_ON_BASIC_SHA256_HASH_SIZE];

  int ndn_encoder_success = 0;
  uint32_t cert_rqst_tlv_val_len = 0;
  uint32_t cert_rqst_sig_tlv_val_len = 0;

  cert_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_DEVICE_IDENTIFIER,
                                                    sign_on_basic_client->device_identifier_len);
  cert_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_N1_PUB,
                                                    sign_on_basic_client->N1_pub_len);
  cert_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_N2_PUB_DIGEST,
                                                    SIGN_ON_BASIC_SHA256_HASH_SIZE);
  cert_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_TRUST_ANCHOR_CERTIFICATE_DIGEST,
                                                    SIGN_ON_BASIC_SHA256_HASH_SIZE);
  cert_rqst_sig_tlv_val_len = sign_on_basic_client->sec_intf.get_cert_rqst_sig_len();
  uint32_t cert_rqst_sig_tlv_len_field_size = encoder_get_var_size(cert_rqst_sig_tlv_val_len);
  uint32_t cert_rqst_sig_tlv_type_field_size = encoder_get_var_size(TLV_SSP_SIGNATURE);
  cert_rqst_tlv_val_len += cert_rqst_sig_tlv_type_field_size;
  cert_rqst_tlv_val_len += cert_rqst_sig_tlv_len_field_size;
  cert_rqst_tlv_val_len += cert_rqst_sig_tlv_val_len;

  uint32_t cert_rqst_tlv_type_field_size = encoder_get_var_size(TLV_SSP_CERTIFICATE_REQUEST);
  uint32_t cert_rqst_tlv_len_field_size = encoder_get_var_size(cert_rqst_tlv_val_len);

  uint32_t cert_rqst_total_len = cert_rqst_tlv_val_len + cert_rqst_tlv_type_field_size + 
                                 cert_rqst_tlv_len_field_size;
  if (buf_len < cert_rqst_total_len) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_BUFFER_TOO_SHORT;
  }

  ndn_encoder_t encoder;
  encoder_init(&encoder, buf_p, buf_len);

  // append the certificate request tlv type and length
  if (encoder_append_type(&encoder, TLV_SSP_CERTIFICATE_REQUEST) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;   
  }
  if (encoder_append_length(&encoder, cert_rqst_tlv_val_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;   
  }
  
  // append the device identifier
  if (encoder_append_type(&encoder, TLV_SSP_DEVICE_IDENTIFIER) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, sign_on_basic_client->device_identifier_len) != ndn_encoder_success)  {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, sign_on_basic_client->device_identifier_p,
                                      sign_on_basic_client->device_identifier_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }

  // append N1 pub
  if (encoder_append_type(&encoder, TLV_SSP_N1_PUB) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, sign_on_basic_client->N1_pub_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, sign_on_basic_client->N1_pub_p,
                                      sign_on_basic_client->N1_pub_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }

  // calculate N2 pub digest
  if (!sign_on_basic_client->sec_intf.gen_sha256_hash(sign_on_basic_client->N2_pub_p, 
    sign_on_basic_client->N2_pub_len, digest_buffer)) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_N2_PUB_HASH;
  }

  // append N2 pub digest
  if (encoder_append_type(&encoder, TLV_SSP_N2_PUB_DIGEST) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, SIGN_ON_BASIC_SHA256_HASH_SIZE) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, digest_buffer,
                                      SIGN_ON_BASIC_SHA256_HASH_SIZE) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }

  // calculate trust anchor cert digest
  if (!sign_on_basic_client->sec_intf.gen_sha256_hash(sign_on_basic_client->trust_anchor_cert_p,
            sign_on_basic_client->trust_anchor_cert_len, digest_buffer)) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_TRUST_ANCHOR_CERT_HASH;
  }

  // append trust anchor cert digest
  if (encoder_append_type(&encoder, TLV_SSP_TRUST_ANCHOR_CERTIFICATE_DIGEST) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, SIGN_ON_BASIC_SHA256_HASH_SIZE) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, digest_buffer,
                                      SIGN_ON_BASIC_SHA256_HASH_SIZE) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }

  uint8_t *sig_payload_begin = buf_p + cert_rqst_tlv_type_field_size + cert_rqst_tlv_len_field_size;
  uint32_t sig_payload_size = encoder.offset - cert_rqst_tlv_type_field_size - cert_rqst_tlv_len_field_size;

  // calculate the signature 
  uint8_t temp_sig_buf[SIG_GENERATION_BUF_LENGTH];
  uint32_t sig_size = 0;
  if (!sign_on_basic_client->sec_intf.gen_cert_rqst_sig(sign_on_basic_client->KS_pri_p,
                                                        sig_payload_begin, sig_payload_size,
                                                        temp_sig_buf, SIG_GENERATION_BUF_LENGTH, 
                                                        &sig_size)) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_SIG;
  }

  if (cert_rqst_sig_tlv_val_len != sig_size) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED;
  }

  encoder_append_type(&encoder, TLV_SSP_SIGNATURE);
  encoder_append_length(&encoder, sig_size);
  encoder_append_raw_buffer_value(&encoder, temp_sig_buf, sig_size);

  *output_len_p = encoder.offset;

  return NDN_SUCCESS;
}

int prcs_cert_rqst_rspns(const uint8_t *cert_rqst_rspns_buf_p,
    uint32_t cert_rqst_rspns_buf_len,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  // declare pointers to KD pri decrypted and KD pub certificate ahead of time,
  // so that modification of internal state of sign on basic client isn't done until after
  // entire certificate request response message is successfully processed
  uint8_t *KD_pri_encrypted_p;
  uint32_t KD_pri_encrypted_len;
  uint8_t *KD_pri_decrypted_p;
  uint32_t KD_pri_decrypted_len;
  uint8_t *KD_pub_cert_p;
  uint32_t KD_pub_cert_len;

  int ndn_decoder_success = 0;
  ndn_decoder_t decoder;
  decoder_init(&decoder, cert_rqst_rspns_buf_p, cert_rqst_rspns_buf_len);

  uint32_t current_tlv_type;
  uint32_t current_tlv_length;
  uint8_t *cert_rqst_rspns_tlv_val_buf_p;
  uint32_t cert_rqst_rspns_tlv_val_len;
  uint8_t *cert_rqst_rspns_tlv_sig_p;

  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_CERT_RQST_RSPNS;
  }
  if (current_tlv_type != TLV_SSP_CERTIFICATE_REQUEST_RESPONSE) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_CERT_RQST_RSPNS;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_CERT_RQST_RSPNS;
  }

  cert_rqst_rspns_tlv_val_buf_p = cert_rqst_rspns_buf_p + decoder.offset;
  cert_rqst_rspns_tlv_val_len = current_tlv_length;

  // check for the KD pri encrypted tlv block and move the decoder offset past it
  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PRI_ENC;
  }
  if (current_tlv_type != TLV_SSP_KD_PRI_ENCRYPTED) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PRI_ENC;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PRI_ENC;
  }
  KD_pri_encrypted_p = cert_rqst_rspns_buf_p + decoder.offset;
  KD_pri_encrypted_len = current_tlv_length;
  if (decoder_move_forward(&decoder, current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PRI_ENC;
  }

  // check for the KD pub certificate tlv block and move the decoder offset past it
  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PUB_CERT;
  }
  if (current_tlv_type != TLV_SSP_KD_PUB_CERTIFICATE) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PUB_CERT;
  } 
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PUB_CERT;
  }
  KD_pub_cert_p = cert_rqst_rspns_buf_p + decoder.offset;
  KD_pub_cert_len = current_tlv_length;
  if (decoder_move_forward(&decoder, current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PUB_CERT;
  }

  // check for signature tlv block and move the decoder to its tlv value

  cert_rqst_rspns_tlv_sig_p = cert_rqst_rspns_buf_p + decoder.offset;

  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }
  if (current_tlv_type != TLV_SSP_SIGNATURE) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }

  const uint8_t *sig_begin = cert_rqst_rspns_buf_p + decoder.offset;
  uint32_t sig_len = current_tlv_length;
  const uint8_t *sig_payload_begin = cert_rqst_rspns_tlv_val_buf_p;
  uint32_t sig_payload_len = cert_rqst_rspns_tlv_sig_p - cert_rqst_rspns_tlv_val_buf_p;

  if (!sign_on_basic_client->sec_intf.vrfy_cert_rqst_rspns_sig(
          sig_payload_begin, sig_payload_len,
          sig_begin, sig_len,
          sign_on_basic_client->KT_p,
          sign_on_basic_client->KT_len)) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_VERIFY_SIGNATURE;
  }

  //***************************************************//

  uint8_t KD_pri_decrypted_temp_buf[SIGN_ON_BASIC_CLIENT_KD_PRI_MAX_LENGTH];

  if (!sign_on_basic_client->sec_intf.decrypt_kd_pri(
      sign_on_basic_client->KT_p,
      sign_on_basic_client->KT_len,
      KD_pri_encrypted_p, KD_pri_encrypted_len,
      KD_pri_decrypted_temp_buf, 
      sizeof(KD_pri_decrypted_temp_buf),
      &KD_pri_decrypted_len)) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_DECRYPT_KD_PRI;
  }

  KD_pri_decrypted_p = KD_pri_decrypted_temp_buf;

  //**********************************************************//

  // now that entire message has been processed successfully, modify internal state of sign on basic client
  memcpy(sign_on_basic_client->KD_pri_p, KD_pri_decrypted_p, KD_pri_decrypted_len);
  sign_on_basic_client->KD_pri_len = KD_pri_decrypted_len;
  memcpy(sign_on_basic_client->KD_pub_cert_p, KD_pub_cert_p, KD_pub_cert_len);
  sign_on_basic_client->KD_pub_cert_len = KD_pub_cert_len;

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_PROCESSED_CERTIFICATE_REQUEST_RESPONSE;
  return NDN_SUCCESS;
}

int cnstrct_fin_msg(uint8_t *buf_p, uint32_t buf_len, uint32_t *output_len_p,
                            struct sign_on_basic_client_t *sign_on_basic_client) {

  int ndn_encoder_success = 0;
  uint32_t fin_msg_tlv_val_len = 0;
  uint32_t fin_msg_sig_tlv_val_len = 0;

  fin_msg_tlv_val_len += encoder_probe_block_size(TLV_SSP_DEVICE_IDENTIFIER,
                                                  sign_on_basic_client->device_identifier_len);
  fin_msg_sig_tlv_val_len = sign_on_basic_client->sec_intf.get_fin_msg_sig_len();
  uint32_t fin_msg_sig_tlv_len_field_size = encoder_get_var_size(fin_msg_sig_tlv_val_len);
  uint32_t fin_msg_sig_tlv_type_field_size = encoder_get_var_size(TLV_SSP_SIGNATURE);
  fin_msg_tlv_val_len += fin_msg_sig_tlv_type_field_size;
  fin_msg_tlv_val_len += fin_msg_sig_tlv_len_field_size;
  fin_msg_tlv_val_len += fin_msg_sig_tlv_val_len;

  uint32_t fin_msg_tlv_type_field_size = encoder_get_var_size(TLV_SSP_BOOTSTRAPPING_REQUEST);
  uint32_t fin_msg_tlv_len_field_size = encoder_get_var_size(fin_msg_tlv_val_len);

  uint32_t fin_msg_total_len = fin_msg_tlv_val_len + fin_msg_tlv_type_field_size + 
                               fin_msg_tlv_len_field_size;
  if (buf_len < fin_msg_total_len) {
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_BUFFER_TOO_SHORT;
  }

  ndn_encoder_t encoder;
  encoder_init(&encoder, buf_p, buf_len);

  // append the fin msg tlv type and length
  if (encoder_append_type(&encoder, TLV_SSP_FINISH_MESSAGE) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_ENCODING_FAILED;   
  }
  if (encoder_append_length(&encoder, fin_msg_tlv_val_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_ENCODING_FAILED;   
  }
  
  // append the device identifier
  if (encoder_append_type(&encoder, TLV_SSP_DEVICE_IDENTIFIER) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, sign_on_basic_client->device_identifier_len) != ndn_encoder_success)  {
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, sign_on_basic_client->device_identifier_p,
                                      sign_on_basic_client->device_identifier_len) != ndn_encoder_success) {
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_ENCODING_FAILED;
  }

  uint8_t *sig_payload_begin = buf_p + fin_msg_tlv_type_field_size + fin_msg_tlv_len_field_size;
  uint32_t sig_payload_size = encoder.offset - fin_msg_tlv_type_field_size - fin_msg_tlv_len_field_size;

  // calculate the signature 
  uint8_t temp_sig_buf[SIG_GENERATION_BUF_LENGTH];
  uint32_t sig_size = 0;
  if (!sign_on_basic_client->sec_intf.gen_fin_msg_sig(sign_on_basic_client->KS_pri_p,
                                                      sig_payload_begin, sig_payload_size,
                                                      temp_sig_buf, SIG_GENERATION_BUF_LENGTH, 
                                                      &sig_size)) {
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_FAILED_TO_GENERATE_SIG;
  }

  if (fin_msg_sig_tlv_val_len != sig_size) {
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_ENCODING_FAILED;
  }

  encoder_append_type(&encoder, TLV_SSP_SIGNATURE);
  encoder_append_length(&encoder, sig_size);
  encoder_append_raw_buffer_value(&encoder, temp_sig_buf, sig_size);

  *output_len_p = encoder.offset;

  return NDN_SUCCESS;
}